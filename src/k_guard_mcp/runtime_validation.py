from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import secrets
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import httpx
import uvicorn

from k_guard_mcp.access_policy import AccessPolicyController, verify_audit_log
from k_guard_mcp.mcp_http_proxy import (
    McpHttpProxySettings,
    create_mcp_http_proxy_app,
    get_mcp_http_proxy_report,
)
from k_guard_mcp.provenance import evidence_bundle, object_artifact


RUNTIME_VALIDATION_SCHEMA = "k_guard_mcp_http_runtime_validation.v1"
_MATRIX_COUNTERS = (
    "requests_post",
    "requests_get",
    "requests_delete",
    "json_responses_forwarded",
    "sse_streams_forwarded",
    "sse_events_forwarded",
    "server_requests_correlated",
    "sessions_deleted",
    "access_decisions_allow",
    "access_decisions_deny",
    "access_tool_lists_filtered",
)


def run_mcp_http_runtime_validation() -> dict[str, Any]:
    runs = [anyio.run(_exercise_once), anyio.run(_exercise_once)]
    official_sdk = _exercise_official_sdk()
    projections = [_projection(run) for run in runs]
    repeat_exact = projections[0] == projections[1]
    report = dict(runs[-1]["report"])
    report.pop("evidence_bundle", None)
    validation = {
        "schema": RUNTIME_VALIDATION_SCHEMA,
        "profile": "synthetic_streamable_http_complete_mediation",
        "complete": all(run["complete"] is True for run in runs) and official_sdk["passed"] is True,
        "passed": all(run["passed"] is True for run in runs) and repeat_exact and official_sdk["passed"] is True,
        "run_count": 2,
        "repeat_exact": repeat_exact,
        "matrix_projection_sha256": hashlib.sha256(_canonical_json(projections[0]).encode("ascii")).hexdigest(),
        "matrix": {name: int(report.get("counts", {}).get(name, 0)) for name in _MATRIX_COUNTERS},
        "checks": runs[-1]["checks"],
        "official_sdk_interoperability": official_sdk,
        "claim_boundary": {
            "synthetic_proxy_interoperability": True,
            "external_mcp_server_certified": False,
            "application_business_logic_certified": False,
        },
        "raw_returned": False,
    }
    report["runtime_validation"] = validation
    report["passed"] = report.get("passed") is True and validation["passed"] is True
    report["complete"] = report.get("complete") is True and validation["complete"] is True
    report["coverage_gap"] = not report["passed"]
    report["evidence_bundle"] = evidence_bundle(
        subject="mcp_streamable_http_runtime",
        producer="k_guard_mcp.runtime_validation",
        artifacts=[object_artifact("runtime-report", report, role="runtime")],
    )
    return report


def _exercise_official_sdk() -> dict[str, Any]:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.fastmcp import FastMCP

    with tempfile.TemporaryDirectory(prefix="k-guard-official-sdk-validation-") as directory:
        # The path is process-created.  Resolve macOS's /var -> /private/var
        # system alias before strict policy/audit symlink checks inspect it.
        root = Path(directory).resolve(strict=True)
        policy_path = root / "access-policy.json"
        audit_path = root / "access-audit.jsonl"
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "k_guard_agent_access_policy.v1",
                    "issuer": "https://validation.example.invalid/k-guard",
                    "audience": "k-guard-official-sdk-validation",
                    "max_ttl_seconds": 120,
                    "roles": {
                        "sdk-reviewer": {
                            "methods": [
                                "initialize",
                                "notifications/initialized",
                                "tools/list",
                                "tools/call",
                                "transport/get",
                                "transport/delete",
                            ],
                            "tools": ["echo"],
                            "resources": ["k-guard://public/*"],
                            "max_calls": 100,
                        }
                    },
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        key = secrets.token_bytes(48)
        controller = AccessPolicyController.from_file(
            policy_path,
            key,
            app_id="official-sdk-app",
            session_id="official-sdk-access-session",
            purpose="official-sdk-interoperability",
            audit_path=audit_path,
            audit_key=key,
        )
        token = controller.mint_grant(
            subject="official-sdk-agent",
            roles=["sdk-reviewer"],
            methods=[
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
                "transport/get",
                "transport/delete",
            ],
            tools=["echo"],
            resources=[],
            ttl_seconds=90,
            max_calls=50,
        )
        upstream_mcp = FastMCP("k-guard-official-upstream", log_level="ERROR")

        @upstream_mcp.tool()
        def echo(text: str) -> str:
            return f"echo:{text}"

        upstream_server = _RunningUvicorn(upstream_mcp.streamable_http_app())
        proxy_app = create_mcp_http_proxy_app(
            f"http://127.0.0.1:{upstream_server.port}/mcp",
            McpHttpProxySettings(
                timeout_seconds=5,
                require_origin=True,
                report_path=root / "official-runtime.json",
            ),
            access_controller=controller,
        )
        proxy_server = _RunningUvicorn(proxy_app)

        async def exercise() -> tuple[str, set[str], str, str | None]:
            async with httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {token}",
                    "Origin": "http://localhost:3000",
                }
            ) as official_client:
                async with streamable_http_client(
                    f"http://127.0.0.1:{proxy_server.port}/mcp",
                    http_client=official_client,
                ) as (read_stream, write_stream, get_session_id):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialized = await session.initialize()
                        tools = await session.list_tools()
                        result = await session.call_tool("echo", {"text": "official"})
                        return (
                            initialized.serverInfo.name,
                            {tool.name for tool in tools.tools},
                            str(result.content[0].text),
                            get_session_id(),
                        )

        try:
            server_name, tools, result_text, session_id = anyio.run(exercise)
            proxy_report = get_mcp_http_proxy_report(proxy_app)
        finally:
            proxy_server.close()
            upstream_server.close()
        checks = {
            "initialize": server_name == "k-guard-official-upstream",
            "tools_list": tools == {"echo"},
            "tools_call": result_text == "echo:official",
            "session_id": bool(session_id),
            "post_get_delete": (
                int(proxy_report.get("counts", {}).get("requests_post", 0)) >= 4
                and int(proxy_report.get("counts", {}).get("requests_get", 0)) >= 1
                and int(proxy_report.get("counts", {}).get("requests_delete", 0)) == 1
            ),
            "access_default_deny": proxy_report.get("access_control", {}).get("default_action") == "deny",
            "audit_chain_verified": verify_audit_log(audit_path, key),
            "no_control_errors": proxy_report.get("control_errors") == [],
        }
        return {
            "passed": all(checks.values()),
            "sdk": "mcp-python-sdk",
            "sdk_version": importlib.metadata.version("mcp"),
            "checks": checks,
            "raw_returned": False,
        }


async def _exercise_once() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="k-guard-runtime-validation-") as directory:
        # The path is process-created.  Resolve macOS's /var -> /private/var
        # system alias before strict policy/audit symlink checks inspect it.
        root = Path(directory).resolve(strict=True)
        policy_path = root / "access-policy.json"
        audit_path = root / "access-audit.jsonl"
        report_path = root / "runtime-report.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "k_guard_agent_access_policy.v1",
                    "issuer": "https://validation.example.invalid/k-guard",
                    "audience": "k-guard-runtime-validation",
                    "max_ttl_seconds": 120,
                    "roles": {
                        "reviewer": {
                            "methods": ["tools/list", "tools/call", "transport/get", "transport/delete"],
                            "tools": ["safe.echo"],
                            "resources": ["k-guard://public/*"],
                            "max_calls": 100,
                        }
                    },
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        key = secrets.token_bytes(48)
        controller = AccessPolicyController.from_file(
            policy_path,
            key,
            app_id="runtime-validation-app",
            session_id="runtime-validation-access-session",
            purpose="streamable-http-control-validation",
            audit_path=audit_path,
            audit_key=key,
        )
        token = controller.mint_grant(
            subject="runtime-validation-agent",
            roles=["reviewer"],
            methods=["tools/list", "tools/call", "transport/get", "transport/delete"],
            tools=["safe.echo"],
            resources=[],
            ttl_seconds=90,
            max_calls=50,
        )
        upstream_authorization_seen = False
        upstream_calls = 0

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            nonlocal upstream_authorization_seen, upstream_calls
            upstream_calls += 1
            upstream_authorization_seen = upstream_authorization_seen or "authorization" in request.headers
            session_headers = {"Mcp-Session-Id": "runtime-session"}
            if request.method == "GET":
                message = {
                    "jsonrpc": "2.0",
                    "id": "server-validation-1",
                    "method": "sampling/createMessage",
                    "params": {"messages": []},
                }
                event = f"event: message\nid: validation-event-1\ndata: {_canonical_json(message)}\n\n"
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/event-stream", **session_headers},
                    content=event.encode("utf-8"),
                    request=request,
                )
            if request.method == "DELETE":
                return httpx.Response(204, headers=session_headers, request=request)
            payload = json.loads(request.content) if request.content else {}
            if not isinstance(payload, dict) or "method" not in payload:
                return httpx.Response(202, headers={"Content-Type": "application/json", **session_headers}, content=b"", request=request)
            if payload.get("method") == "tools/list":
                result = {"tools": [{"name": "safe.echo"}, {"name": "admin.delete"}]}
            else:
                result = {"ok": True}
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json", **session_headers},
                json={"jsonrpc": "2.0", "id": payload.get("id"), "result": result},
                request=request,
            )

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        settings = McpHttpProxySettings(
            report_path=report_path,
            require_origin=True,
            forward_authorization=False,
        )
        app = create_mcp_http_proxy_app(
            "http://upstream.invalid/mcp",
            settings,
            http_client=upstream,
            access_controller=controller,
        )
        downstream = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://proxy.invalid",
        )
        common = {
            "Origin": "http://localhost:3000",
            "Authorization": f"Bearer {token}",
        }
        post_headers = {
            **common,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        try:
            tools = await downstream.post(
                "/mcp",
                headers=post_headers,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            allowed = await downstream.post(
                "/mcp",
                headers=post_headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "safe.echo", "arguments": {}}},
            )
            denied = await downstream.post(
                "/mcp",
                headers=post_headers,
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "admin.delete", "arguments": {}}},
            )
            stream = await downstream.get(
                "/mcp",
                headers={**common, "Accept": "text/event-stream", "Mcp-Session-Id": "runtime-session"},
            )
            server_response = await downstream.post(
                "/mcp",
                headers={**post_headers, "Mcp-Session-Id": "runtime-session"},
                json={"jsonrpc": "2.0", "id": "server-validation-1", "result": {"accepted": True}},
            )
            deleted = await downstream.delete(
                "/mcp",
                headers={**common, "Mcp-Session-Id": "runtime-session"},
            )
            visible_tools = tools.json().get("result", {}).get("tools", []) if tools.status_code == 200 else []
            checks = {
                "tools_filtered": [item.get("name") for item in visible_tools if isinstance(item, dict)] == ["safe.echo"],
                "allowed_tool_forwarded": allowed.status_code == 200,
                "denied_tool_blocked": denied.status_code == 403,
                "sse_server_request_forwarded": stream.status_code == 200 and "server-validation-1" in stream.text,
                "server_response_correlated": server_response.status_code == 202,
                "session_deleted": deleted.status_code == 204,
                "authorization_not_forwarded": not upstream_authorization_seen,
                "audit_chain_verified": verify_audit_log(audit_path, key),
            }
            report = get_mcp_http_proxy_report(app)
            matrix_complete = all(int(report.get("counts", {}).get(name, 0)) > 0 for name in _MATRIX_COUNTERS)
            passed = (
                all(checks.values())
                and matrix_complete
                and report.get("complete") is True
                and report.get("passed") is True
                and report.get("finding_count") == 0
                and upstream_calls == 5
            )
            return {
                "complete": passed,
                "passed": passed,
                "checks": {**checks, "matrix_complete": matrix_complete, "expected_upstream_call_count": upstream_calls == 5},
                "report": report,
            }
        finally:
            await downstream.aclose()
            await upstream.aclose()


def _projection(run: dict[str, Any]) -> dict[str, Any]:
    report = run.get("report", {}) if isinstance(run.get("report"), dict) else {}
    counts = report.get("counts", {}) if isinstance(report.get("counts"), dict) else {}
    return {
        "complete": run.get("complete"),
        "passed": run.get("passed"),
        "checks": dict(run.get("checks", {})),
        "matrix": {name: int(counts.get(name, 0)) for name in _MATRIX_COUNTERS},
        "finding_count": report.get("finding_count"),
        "control_error_count": len(report.get("control_errors", [])) if isinstance(report.get("control_errors"), list) else -1,
    }


class _RunningUvicorn:
    def __init__(self, app: Any) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(128)
        self.port = int(self.socket.getsockname()[1])
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_level="error",
                lifespan="on",
            )
        )
        self.thread = threading.Thread(
            target=self._run_server,
            name=f"k-guard-runtime-validation-{self.port}",
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self.server.started:
            self.close()
            raise RuntimeError("runtime_validation_server_start_failed")

    def _run_server(self) -> None:
        if sys.platform == "win32":
            # Keep the validation-only loop local to this thread.  Windows
            # Proactor transports can retain a reset MCP connection during
            # Uvicorn shutdown; the selector loop avoids that transport path
            # without changing the process-wide event-loop policy.
            with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
                runner.run(self.server.serve(sockets=[self.socket]))
            return
        self.server.run(sockets=[self.socket])

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            self.server.force_exit = True
            self.thread.join(timeout=10)
        # Uvicorn owns the supplied listener through shutdown and wait_closed.
        # Only the final cleanup path closes a still-open socket from here.
        if self.socket.fileno() != -1:
            self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError("runtime_validation_server_stop_failed")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


__all__ = ["RUNTIME_VALIDATION_SCHEMA", "run_mcp_http_runtime_validation"]
