from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def _rule_ids(report: dict) -> set[str]:
    return {str(item.get("rule_id")) for item in report.get("findings", [])}


def test_tool_argument_budgets_and_sca_authorization_fail_closed(tmp_path: Path) -> None:
    from k_guard_mcp import server

    oversized = "x" * 100_000
    reports = [
        server.software_composition_audit(oversized),
        server.validate_policy_controls(oversized),
        server.validate_streamable_http_runtime(oversized),
        server.create_benchmark_template(oversized),
        server.create_field_campaign_template(oversized),
        server.field_campaign_status(oversized, "status.json"),
        server.field_campaign_status("roster.csv", oversized),
        server.field_benchmark(oversized),
        server.field_benchmark("manifest.csv", oversized),
        server.create_guardian_manifest_template(oversized),
        server.explain_rule(oversized),
        server.suggest_fix(oversized),
    ]
    assert all("MCP_ARGUMENT_BUDGET_EXCEEDED" in _rule_ids(report) for report in reports)

    unauthorized = server.software_composition_audit(str(tmp_path), authorize_advisory_lookup=False)
    assert _rule_ids(unauthorized) == {"MCP_SCA_AUTHORIZATION_REQUIRED"}


def test_validation_tools_write_only_sanitized_stub_reports(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    control_output = tmp_path / "control.json"
    runtime_output = tmp_path / "runtime.json"
    monkeypatch.setattr(server, "run_control_validation", lambda: {"passed": True, "token": "control"})
    monkeypatch.setattr(server, "run_mcp_http_runtime_validation", lambda: {"passed": True, "token": "runtime"})

    control = server.validate_policy_controls(str(control_output))
    runtime = server.validate_streamable_http_runtime(str(runtime_output))

    assert control == json.loads(control_output.read_text(encoding="utf-8"))
    assert runtime == json.loads(runtime_output.read_text(encoding="utf-8"))


def test_field_probe_requires_both_local_and_external_opt_in(monkeypatch) -> None:
    from k_guard_mcp import server

    monkeypatch.delenv(server.PROBE_OPT_IN_ENV, raising=False)
    monkeypatch.delenv(server.EXTERNAL_PROBE_OPT_IN_ENV, raising=False)
    local_block = server.field_benchmark("manifest.csv", run_probes=True)
    assert _rule_ids(local_block) == {"MCP_PROBE_DISABLED_BY_DEFAULT"}

    monkeypatch.setenv(server.PROBE_OPT_IN_ENV, "1")
    external_block = server.field_benchmark("manifest.csv", run_probes=True)
    assert _rule_ids(external_block) == {"MCP_EXTERNAL_PROBE_DISABLED_BY_DEFAULT"}


def test_workspace_budget_invalid_config_and_exhaustion_are_findings(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    monkeypatch.setenv("K_GUARD_MCP_MAX_FILES", "not-an-int")
    invalid = server._workspace_budget_finding(str(tmp_path), "test")
    assert invalid is not None
    assert invalid.rule_id == "MCP_WORKSPACE_BUDGET_CONFIG_INVALID"

    monkeypatch.setenv("K_GUARD_MCP_MAX_FILES", "1")
    monkeypatch.setenv("K_GUARD_MCP_MAX_MB", "1")
    (tmp_path / "one.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "two.ts").write_text("export const two = 2\n", encoding="utf-8")
    exceeded = server._workspace_budget_finding(str(tmp_path), "test")
    assert exceeded is not None
    assert exceeded.rule_id == "MCP_WORKSPACE_SCAN_BUDGET_EXCEEDED"


def test_session_header_file_rejects_ambiguous_or_empty_shapes(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    monkeypatch.chdir(tmp_path)
    target_url = "http://127.0.0.1:3100"
    expires_at = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    session_file = tmp_path / "session.json"
    invalid_payloads = [
        [],
        {"origin": target_url, "expires_at": expires_at, "headers": []},
        {"origin": target_url, "expires_at": expires_at, "headers": {"Host": "example.test"}},
    ]
    for payload in invalid_payloads:
        session_file.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            server._load_session_headers_file(str(session_file), target_url)

    session_file.write_text(
        json.dumps(
            {
                "origin": target_url,
                "expires_at": expires_at,
                "headers": {"Authorization": "Bearer test-only"},
            }
        ),
        encoding="utf-8",
    )
    assert server._load_session_headers_file(str(session_file), target_url).headers == {"Authorization": "Bearer test-only"}
