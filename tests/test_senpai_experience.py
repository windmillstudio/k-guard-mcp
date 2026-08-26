import copy
import importlib.util
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import get_type_hints
from unittest.mock import patch

import anyio
import pytest

from k_guard_mcp.experience import apply_senpai_experience


pytestmark = pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="MCP SDK is not installed")


def _write_substantive_app(root: Path) -> None:
    (root / "route.ts").write_text(
        "export async function GET() {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )


def _structured_tool_payload(result) -> dict:
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


class _HealthyAppHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # type: ignore[no-untyped-def]
        return

    def do_GET(self) -> None:
        if self.path not in {"/", "/api/health"}:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()


def test_generic_experience_is_ordered_raw_free_and_preserves_core_result() -> None:
    from k_guard_mcp import server

    raw = "name: 홍길동 phone=010-9876-5432 token=sk-thisisaverylongfakeapikey321"
    report = server.scanner.scan_text(raw, "inline-test").to_dict()
    core_result = copy.deepcopy(report)

    returned = apply_senpai_experience(report, tool_name="scan_text", inspected_scope="inline_text")

    assert {key: value for key, value in returned.items() if key != "experience"} == core_result
    assert list(returned["experience"]) == ["verdict", "why", "next_actions", "presentation", "details"]
    assert len(returned["experience"]["next_actions"]) <= 3
    assert returned["experience"]["details"]["persona"] == "안경선배"
    assert returned["experience"]["details"]["release_authority"] is False
    presentation = returned["experience"]["details"]["presentation"]
    assert presentation["order"] == ["verdict", "why", "next_actions", "details"]
    assert presentation["verdict"] == returned["experience"]["verdict"]
    payload = json.dumps(returned, ensure_ascii=False)
    assert "홍길동" not in payload
    assert "010-9876-5432" not in payload
    assert "sk-thisisaverylongfakeapikey321" not in payload


def test_scan_probe_runtime_and_quick_gate_share_the_generic_experience_shape() -> None:
    from k_guard_mcp import server

    with patch.dict("os.environ", {}, clear=True):
        reports = [
            server.scan_text("const value = 1"),
            server.probe_http("http://127.0.0.1:9"),
            server.observe_mcp_events(json.dumps({"event": "tool_call", "tool": "local.read"})),
            server.security_gate("missing-workspace-for-senpai-test", fail_on="high"),
        ]

    for report in reports:
        assert list(report["experience"]) == ["verdict", "why", "next_actions", "presentation", "details"]
        assert len(report["experience"]["next_actions"]) <= 3
        assert report["experience"]["details"]["canonical_release_tool"] == "start_review_before_ship"
        assert report["experience"]["details"]["canonical_release_engine"] == "review_before_ship"
        assert report["experience"]["details"]["raw_returned"] is False
    assert reports[1]["experience"]["verdict"]["code"] == "hold_incomplete"
    assert reports[3]["security_gate"]["passed"] is False
    assert reports[3]["experience"]["verdict"]["code"] == "hold_incomplete"


def test_incomplete_review_still_surfaces_confirmed_blocking_risk() -> None:
    report = {
        "findings": [
            {
                "rule_id": "MCP_SCAN_FAILED",
                "severity": "high",
                "recommendation": "워크스페이스 경로를 확인하고 같은 범위로 다시 실행하세요.",
            },
            {"rule_id": "APP_CONFIRMED_RISK", "severity": "high"},
        ],
        "security_gate": {"control_failed": True},
    }

    returned = apply_senpai_experience(report, tool_name="security_gate", inspected_scope="workspace")

    assert returned["experience"]["verdict"]["code"] == "hold_incomplete"
    assert "critical/high 위험이 1건" in returned["experience"]["why"]
    assert returned["experience"]["next_actions"] == [
        "검수 미완료 규칙: MCP_SCAN_FAILED",
        "복구 후 같은 도구와 범위로 다시 실행: 워크스페이스 경로를 확인하고 같은 범위로 다시 실행하세요.",
        "이미 확인된 차단 위험 수정: APP_CONFIRMED_RISK",
    ]


def test_real_empty_workspace_control_finding_uses_model_recommendation() -> None:
    from k_guard_mcp import server

    with tempfile.TemporaryDirectory() as tmp:
        report = server.security_gate(tmp, fail_on="high")

    assert report["experience"]["details"]["control_rule_ids"] == ["MCP_SECURITY_GATE_WORKSPACE_EMPTY"]
    assert report["experience"]["next_actions"][0] == "검수 미완료 규칙: MCP_SECURITY_GATE_WORKSPACE_EMPTY"
    assert "Point security_gate at a workspace" in report["experience"]["next_actions"][1]


def test_fastmcp_discovers_primary_tools_prompt_and_keeps_legacy_tools() -> None:
    from k_guard_mcp import server

    async def exercise(root: str):
        mcp_server = server.create_mcp_server()
        tools = await mcp_server.list_tools()
        prompts = await mcp_server.list_prompts()
        guided = await mcp_server.get_prompt("guided_review")
        started_result = await mcp_server.call_tool("check_my_app", {"path": root, "include_flow": True})
        started = _structured_tool_payload(started_result)
        completed_result = await mcp_server.call_tool(
            "continue_review",
            {"review_id": started["review_job"]["review_id"], "wait_seconds": 4},
        )
        return mcp_server.instructions, tools, prompts, guided, started, _structured_tool_payload(completed_result)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_substantive_app(root)
        instructions, tools, prompts, guided, started, completed = anyio.run(exercise, str(root))

    tool_names = [tool.name for tool in tools]
    assert tool_names[:3] == ["check_my_app", "continue_review", "start_review_before_ship"]
    assert "review_before_ship" not in tool_names
    assert {"guardian_audit", "scan_workspace", "scan_text", "security_gate"}.issubset(tool_names)
    assert {prompt.name for prompt in prompts} == {"guided_review"}
    primary_tools = {tool.name: tool for tool in tools[:3]}
    assert all(primary_tools[name].outputSchema for name in primary_tools)
    assert all(
        set(primary_tools[name].outputSchema["required"]) >= {"method", "experience"}
        for name in primary_tools
    )
    assert all(
        get_type_hints(tool)["return"] == dict[str, object]
        for tool in (server.check_my_app, server.continue_review, server.start_review_before_ship)
    )
    release_schema = primary_tools["start_review_before_ship"].inputSchema
    assert release_schema["required"] == [
        "initial_review_id",
        "app_id",
        "business_purpose",
        "data_classes",
        "user_scope",
        "scope_proof_ref",
    ]
    assert all(
        release_schema["properties"][name].get("description")
        for name in release_schema["required"]
    )
    assert "check_my_app" in instructions
    assert "review_before_ship" in instructions
    assert "HOLD" in guided.messages[0].content.text
    assert started["review_job"]["no_release_before_complete"] is True
    assert started["review_job"]["next_tool"] == "start_review_before_ship"
    assert "start_review_before_ship 단계" in started["experience"]["next_actions"][2]
    assert started["experience"]["verdict"]["code"] == "review_in_progress"
    assert completed["primary_workflow"]["canonical_release_authority"] is False
    assert completed["experience"]["details"]["tool"] == "check_my_app"


def test_internal_review_before_ship_uses_ephemeral_guardian_high_and_holds_incomplete_scope() -> None:
    from k_guard_mcp import server

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_substantive_app(root)
        report = server.review_before_ship(workspace_path=str(root), app_id="demo-app")
        payload = json.dumps(report, ensure_ascii=False)
        assert str(root) not in payload

    assert report["method"] == "guardian_audit"
    assert report["guardian_gate"]["fail_on"] == "high"
    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["canonical_release_authority"] is False
    assert report["review_contract"]["profile"] == "korean_senior"
    assert {"site_security", "api_exposure", "data_management"}.issubset(
        report["review_contract"]["missing_review_domains"]
    )
    assert report["experience"]["verdict_code"] == "hold_coverage"
    assert report["experience"]["presentation"]["verdict"]["code"] == "hold_coverage"
    assert report["experience"]["presentation"]["order"] == ["verdict", "why", "next_actions", "details"]
    assert report["primary_workflow"]["ephemeral_explicit_manifest"] is True
    assert report["primary_workflow"]["manifest_retained"] is False
    assert report["primary_workflow"]["business_context_supplied"] is False
    assert report["primary_workflow"]["scope_assertion_supplied"] is False
    assert report["primary_workflow"]["live_target_supplied"] is False
    manifest_artifact = next(
        artifact for artifact in report["evidence_bundle"]["artifacts"] if artifact["label"] == "guardian_manifest"
    )
    assert manifest_artifact["exists_at_bundle_time"] is True
    assert manifest_artifact["raw_returned"] is False


def test_review_before_ship_internal_error_fails_closed_without_echoing_error() -> None:
    from k_guard_mcp import server

    raw_error = "boom user@example.com sk-thisisaverylongfakeapikey999"
    with patch.object(server, "_write_review_before_ship_manifest", side_effect=RuntimeError(raw_error)):
        report = server.review_before_ship(workspace_path=".", app_id="demo-app")
    payload = json.dumps(report, ensure_ascii=False)

    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["canonical_release_authority"] is False
    assert report["primary_workflow"]["fail_closed"] is True
    assert report["primary_workflow"]["canonical_release_authority"] is False
    assert {finding["rule_id"] for finding in report["findings"]} == {"MCP_REVIEW_BEFORE_SHIP_FAILED"}
    assert "user@example.com" not in payload
    assert "sk-thisisaverylongfakeapikey999" not in payload


def test_review_before_ship_holds_until_product_qualification_evidence_is_supplied() -> None:
    from k_guard_mcp import server

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_substantive_app(root)
        http_server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthyAppHandler)
        thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(
                os.environ,
                {
                    "K_GUARD_MCP_ENABLE_PROBE": "1",
                    "K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE": "1",
                    "K_GUARD_EVIDENCE_HMAC_KEY": "operator-test-key-with-at-least-thirty-two-bytes-123",
                },
            ):
                report = server.review_before_ship(
                    workspace_path=str(root),
                    app_id="demo-app",
                    business_purpose="owned demo health service",
                    data_classes="public_content",
                    user_scope="public health-check users",
                    scope_proof_ref="operator-owned local fixture",
                    live_url=f"http://127.0.0.1:{http_server.server_port}",
                    public_endpoints="/,/api/health",
                    run_live_review=True,
                )
        finally:
            http_server.shutdown()
            thread.join(timeout=5)

    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["canonical_release_authority"] is False
    assert report["guardian_gate"]["review_contract_passed"] is True
    assert report["guardian_gate"]["release_qualification_passed"] is False
    assert report["review_contract"]["missing_review_domains"] == []
    assert report["experience"]["verdict_code"] == "hold_qualification"
    assert report["experience"]["presentation"]["verdict"]["code"] == "hold_qualification"
    assert report["application_assurance"]["passed"] is True
    assert report["application_assurance"]["status"] == "clear_in_reviewed_scope"
    assert report["application_assurance"]["release_authority"] is False
    assert report["experience"]["application_assurance"] == report["application_assurance"]
    assert report["primary_workflow"]["canonical_release_authority"] is False
