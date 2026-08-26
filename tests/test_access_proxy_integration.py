from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import anyio
import httpx

from k_guard_mcp.access_policy import AccessPolicyController, load_policy, verify_audit_log
from k_guard_mcp.mcp_http_proxy import (
    McpHttpProxySettings,
    create_mcp_http_proxy_app,
    get_mcp_http_proxy_report,
)
from k_guard_mcp.mcp_proxy import run_stdio_proxy


KEY = b"k-guard-proxy-integration-key-32-bytes-minimum-2026"


def _controller(tmp_path: Path, *, session: str = "review-session") -> AccessPolicyController:
    policy_path = tmp_path / "access-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema": "k_guard_agent_access_policy.v1",
                "issuer": "https://issuer.example.test/k-guard",
                "audience": "k-guard-proxy",
                "max_ttl_seconds": 120,
                "roles": {
                    "reviewer": {
                        "methods": [
                            "initialize",
                            "notifications/initialized",
                            "tools/list",
                            "tools/call",
                            "transport/get",
                            "transport/delete",
                        ],
                        "tools": ["safe.echo"],
                        "resources": [],
                        "max_calls": 20,
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return AccessPolicyController(
        load_policy(policy_path),
        KEY,
        app_id="app-one",
        session_id=session,
        purpose="release-review",
        audit_path=tmp_path / "access-audit.jsonl",
    )


def _token(controller: AccessPolicyController, *, subject: str = "agent-a") -> str:
    return controller.mint_grant(
        subject=subject,
        roles=["reviewer"],
        methods=[
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
            "transport/get",
            "transport/delete",
        ],
        tools=["safe.echo"],
        resources=[],
        ttl_seconds=60,
        max_calls=20,
    )


def _request(request_id: int, tool: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"value": "hello"}},
    }


def test_http_proxy_requires_grant_blocks_denied_tool_and_never_forwards_grant(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token = _token(controller)
    upstream_calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        request_id = json.loads(request.content)["id"]
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": request_id, "result": {"ok": True}},
            request=request,
        )

    async def exercise() -> tuple[object, httpx.Response, httpx.Response, httpx.Response]:
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app = create_mcp_http_proxy_app(
            "http://upstream.test/mcp",
            McpHttpProxySettings(report_path=tmp_path / "runtime.json"),
            http_client=upstream,
            access_controller=controller,
        )
        downstream = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://proxy.test",
        )
        try:
            missing = await downstream.post(
                "/mcp",
                headers={"Content-Type": "application/json"},
                json=_request(1, "safe.echo"),
            )
            denied = await downstream.post(
                "/mcp",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                json=_request(2, "admin.delete"),
            )
            allowed = await downstream.post(
                "/mcp",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                json=_request(3, "safe.echo"),
            )
            return app, missing, denied, allowed
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, missing, denied, allowed = anyio.run(exercise)

    assert missing.status_code == 401
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == -32003
    assert allowed.status_code == 200
    assert len(upstream_calls) == 1
    assert "authorization" not in upstream_calls[0].headers
    report = get_mcp_http_proxy_report(app)
    assert report["access_control"]["default_action"] == "deny"
    assert report["access_control"]["decision_counts"]["deny"] >= 1
    assert report["policy"]["audit_persistence"]["healthy"] is True
    assert verify_audit_log(tmp_path / "access-audit.jsonl", KEY) is True


def test_http_proxy_filters_tools_list_and_binds_lifecycle_to_principal(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token = _token(controller)

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"tools": [{"name": "safe.echo"}, {"name": "admin.delete"}]},
            },
            request=request,
        )

    async def exercise() -> tuple[object, httpx.Response]:
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app = create_mcp_http_proxy_app(
            "http://upstream.test/mcp",
            McpHttpProxySettings(report_path=tmp_path / "runtime.json"),
            http_client=upstream,
            access_controller=controller,
        )
        downstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test")
        try:
            response = await downstream.post(
                "/mcp",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    assert response.status_code == 200
    assert [item["name"] for item in response.json()["result"]["tools"]] == ["safe.echo"]
    assert get_mcp_http_proxy_report(app)["counts"]["access_tool_lists_filtered"] == 1


def test_http_mcp_session_server_request_cannot_be_claimed_by_another_principal(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token_a = _token(controller, subject="agent-a")
    token_b = _token(controller, subject="agent-b")
    forwarded_client_responses = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal forwarded_client_responses
        payload = json.loads(request.content)
        if "method" in payload:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-one"},
                json=[
                    {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}},
                    {"jsonrpc": "2.0", "id": 77, "method": "sampling/createMessage", "params": {}},
                ],
                request=request,
            )
        forwarded_client_responses += 1
        return httpx.Response(202, headers={"Content-Type": "application/json"}, content=b"", request=request)

    async def exercise() -> tuple[httpx.Response, httpx.Response, httpx.Response]:
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app = create_mcp_http_proxy_app(
            "http://upstream.test/mcp",
            McpHttpProxySettings(report_path=tmp_path / "runtime.json"),
            http_client=upstream,
            access_controller=controller,
        )
        downstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test")
        try:
            opened = await downstream.post(
                "/mcp",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_a}"},
                json=_request(10, "safe.echo"),
            )
            response_payload = {"jsonrpc": "2.0", "id": 77, "result": {"model": "ok"}}
            stolen = await downstream.post(
                "/mcp",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token_b}",
                    "Mcp-Session-Id": "session-one",
                },
                json=response_payload,
            )
            owner = await downstream.post(
                "/mcp",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token_a}",
                    "Mcp-Session-Id": "session-one",
                },
                json=response_payload,
            )
            return opened, stolen, owner
        finally:
            await downstream.aclose()
            await upstream.aclose()

    opened, stolen, owner = anyio.run(exercise)
    assert opened.status_code == 200
    assert stolen.status_code == 400
    assert owner.status_code == 202
    assert forwarded_client_responses == 1


def test_stdio_proxy_enforces_grant_and_preserves_initialize_protocol_version(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token = _token(controller)
    upstream = tmp_path / "stdio_upstream.py"
    upstream.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    message = json.loads(line)\n"
        "    if message.get('method') == 'initialize':\n"
        "        result = {'protocolVersion': message['params']['protocolVersion']}\n"
        "    else:\n"
        "        result = {'tool': message.get('params', {}).get('name')}\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}), flush=True)\n",
        encoding="utf-8",
    )
    client_input = io.StringIO(
        "\n".join(
            json.dumps(item)
            for item in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
                },
                _request(2, "admin.delete"),
                _request(3, "safe.echo"),
            )
        )
        + "\n"
    )
    output = io.StringIO()
    report_path = tmp_path / "stdio-report.json"

    code = run_stdio_proxy(
        [sys.executable, "-u", str(upstream)],
        report_path=report_path,
        client_input=client_input,
        protocol_output=output,
        diagnostic_output=io.StringIO(),
        access_controller=controller,
        access_token=token,
    )

    messages = [json.loads(line) for line in output.getvalue().splitlines()]
    by_id = {message["id"]: message for message in messages}
    assert code == 0
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    assert by_id[2]["error"]["message"] == "K-Guard access policy denied the request"
    assert by_id[3]["result"]["tool"] == "safe.echo"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["access_control"]["default_action"] == "deny"
    assert report["stats"]["access_decisions_deny"] == 1
    assert "2025-06-18" not in json.dumps(report)
