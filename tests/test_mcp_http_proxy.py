from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import anyio
import httpx
import pytest
import uvicorn
from starlette.applications import Starlette

import k_guard_mcp.mcp_http_proxy as proxy_module
from k_guard_mcp.mcp_http_proxy import (
    McpHttpProxySettings,
    create_mcp_http_proxy_app,
    get_mcp_http_proxy_report,
)
from k_guard_mcp.provenance import verify_evidence_bundle


POST_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def _request(request_id: Any = 1, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": params or {"name": "echo", "arguments": {"text": "hello"}},
    }


async def _proxy_client(
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
    *,
    settings: McpHttpProxySettings | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[Any, httpx.AsyncClient, httpx.AsyncClient]:
    upstream_transport = transport or httpx.MockTransport(handler)
    upstream = httpx.AsyncClient(transport=upstream_transport, follow_redirects=True)
    app = create_mcp_http_proxy_app(
        "http://upstream.test/mcp",
        settings,
        http_client=upstream,
    )
    downstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy.test",
    )
    return app, upstream, downstream


async def _raw_asgi_exchange(
    app: Any,
    *,
    method: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    messages: list[dict[str, Any]] | None = None,
    receive: Callable[[], Any] | None = None,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    pending = list(messages or [{"type": "http.request", "body": b"", "more_body": False}])
    sent: list[dict[str, Any]] = []

    async def default_receive() -> dict[str, Any]:
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 43100),
        "server": ("proxy.test", 80),
    }
    await app(scope, receive or default_receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return int(start["status"]), list(start.get("headers", [])), body


def _proxy_for(app: Any) -> Any:
    return app.routes[0].endpoint.proxy


def test_post_json_allow_forwards_only_transport_headers_and_writes_raw_free_report(tmp_path: Path):
    seen: list[httpx.Request] = []
    report_path = tmp_path / "proxy-report.json"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        return httpx.Response(
            201,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-1"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}},
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(
            upstream_handler,
            settings=McpHttpProxySettings(report_path=report_path),
        )
        try:
            response = await downstream.post(
                "/mcp",
                headers={
                    **POST_HEADERS,
                    "Origin": "http://localhost:4310",
                    "MCP-Protocol-Version": "2025-11-25",
                    "Last-Event-ID": "event-4",
                    "Authorization": "Bearer must-not-forward",
                    "Cookie": "session=must-not-forward",
                    "X-Untrusted": "must-not-forward",
                },
                json=_request(),
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)

    assert response.status_code == 201
    assert response.headers["mcp-session-id"] == "session-1"
    assert response.json()["result"] == {"ok": True}
    assert len(seen) == 1
    forwarded = seen[0].headers
    assert forwarded["accept"] == POST_HEADERS["Accept"]
    assert forwarded["content-type"] == "application/json"
    assert forwarded["mcp-protocol-version"] == "2025-11-25"
    assert forwarded["last-event-id"] == "event-4"
    assert "authorization" not in forwarded
    assert "cookie" not in forwarded
    assert "origin" not in forwarded
    assert "x-untrusted" not in forwarded
    assert set(forwarded) == {
        "host",
        "accept",
        "content-type",
        "mcp-protocol-version",
        "last-event-id",
        "content-length",
    }

    report = get_mcp_http_proxy_report(app)
    persisted = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["transport"] == "streamable_http"
    assert report["raw_free"] is True
    assert report["complete"] is True
    assert report["passed"] is True
    assert report["execution"]["runtime_exercised"] is True
    assert verify_evidence_bundle(report["evidence_bundle"]) is True
    assert report["counts"]["post_requests_forwarded"] == 1
    assert report["hashes"]["request_body"]["count"] == 1
    assert persisted == report
    assert "http://upstream.test/mcp" not in json.dumps(report)
    assert "must-not-forward" not in json.dumps(report)


def test_unexercised_proxy_is_complete_but_not_release_ready():
    app = create_mcp_http_proxy_app("http://upstream.test/mcp")

    report = get_mcp_http_proxy_report(app)

    assert report["complete"] is True
    assert report["passed"] is False
    assert report["coverage_gap"] is True
    assert report["control_status"] == "not_exercised"
    assert report["execution"]["runtime_exercised"] is False
    assert verify_evidence_bundle(report["evidence_bundle"]) is True


def test_post_json_policy_block_never_reaches_upstream():
    calls = 0
    secret = "sk-thisisaverylongfakeapikey000"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json=_request(params={"name": "echo", "arguments": {"token": secret}}),
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    payload = response.text
    report_payload = json.dumps(get_mcp_http_proxy_report(app), ensure_ascii=False)

    assert response.status_code == 403
    assert calls == 0
    assert response.json()["error"]["code"] == -32003
    assert response.json()["error"]["data"]["raw_content_forwarded"] is False
    assert secret not in payload
    assert secret not in report_payload


def test_post_json_redacts_both_directions_before_forwarding():
    client_email = "client@example.com"
    server_email = "server@example.com"
    forwarded: list[dict[str, Any]] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        forwarded.append(json.loads(request.content))
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 7, "result": {"email": server_email}},
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json=_request(7, params={"name": "echo", "arguments": {"email": client_email}}),
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    combined = response.text + json.dumps(forwarded, ensure_ascii=False)
    report_text = json.dumps(get_mcp_http_proxy_report(app), ensure_ascii=False)

    assert response.status_code == 200
    assert client_email not in combined
    assert server_email not in combined
    assert forwarded[0]["params"]["arguments"]["email"].startswith("<redacted:EMAIL:")
    assert response.json()["result"]["email"].startswith("<redacted:EMAIL:")
    assert client_email not in report_text
    assert server_email not in report_text


def test_origin_outside_explicit_allowlist_is_rejected():
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(
            upstream_handler,
            settings=McpHttpProxySettings(allowed_origins=("https://trusted.example",)),
        )
        try:
            return await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Origin": "https://evil.example"},
                json=_request(),
            )
        finally:
            await downstream.aclose()
            await upstream.aclose()

    response = anyio.run(exercise)
    assert response.status_code == 403
    assert calls == 0
    assert response.json()["error"]["data"]["raw_content_forwarded"] is False


def test_request_size_limit_fails_before_upstream():
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(
            upstream_handler,
            settings=McpHttpProxySettings(max_request_bytes=96),
        )
        try:
            return await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                content=json.dumps(_request(params={"value": "x" * 256})).encode(),
            )
        finally:
            await downstream.aclose()
            await upstream.aclose()

    response = anyio.run(exercise)
    assert response.status_code == 413
    assert calls == 0


class _SlowTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await anyio.sleep(0.2)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
            request=request,
        )


def test_upstream_timeout_fails_closed_and_marks_report_incomplete():
    async def exercise():
        app, upstream, downstream = await _proxy_client(
            settings=McpHttpProxySettings(timeout_seconds=0.03),
            transport=_SlowTransport(),
        )
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == 504
    assert report["complete"] is False
    assert report["passed"] is False
    assert {error["kind"] for error in report["control_errors"]} == {"upstream_timeouts"}


def test_upstream_redirect_is_not_followed():
    calls: list[str] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(307, headers={"Location": "http://other-host.test/mcp"})

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report_text = json.dumps(get_mcp_http_proxy_report(app))
    assert response.status_code == 502
    assert calls == ["http://upstream.test/mcp"]
    assert "other-host.test" not in report_text
    assert get_mcp_http_proxy_report(app)["complete"] is False


def test_session_header_is_preserved_and_authorization_is_configurable():
    seen: list[httpx.Request] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {}},
        )

    async def call(forward_authorization: bool):
        app, upstream, downstream = await _proxy_client(
            upstream_handler,
            settings=McpHttpProxySettings(forward_authorization=forward_authorization),
        )
        try:
            return await downstream.post(
                "/mcp",
                headers={
                    **POST_HEADERS,
                    "Mcp-Session-Id": "session-a",
                    "Authorization": "Bearer configured-token",
                },
                json=_request(len(seen) + 1),
            )
        finally:
            await downstream.aclose()
            await upstream.aclose()

    first = anyio.run(call, False)
    second = anyio.run(call, True)

    assert first.headers["mcp-session-id"] == "session-a"
    assert second.headers["mcp-session-id"] == "session-a"
    assert seen[0].headers["mcp-session-id"] == "session-a"
    assert "authorization" not in seen[0].headers
    assert seen[1].headers["authorization"] == "Bearer configured-token"


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            await anyio.sleep(0)
            yield chunk


class _DelayedChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunk: bytes, delay: float = 0.1) -> None:
        self.chunk = chunk
        self.delay = delay

    async def __aiter__(self):
        await anyio.sleep(self.delay)
        yield self.chunk


class _FailingChunkStream(httpx.AsyncByteStream):
    def __init__(self, error: BaseException) -> None:
        self.error = error

    async def __aiter__(self):
        if False:
            yield b""
        raise self.error


def test_get_sse_preserves_framing_and_correlates_server_request_response():
    calls: list[httpx.Request] = []
    server_request = {
        "jsonrpc": "2.0",
        "id": "server-7",
        "method": "sampling/createMessage",
        "params": {"messages": []},
    }
    event = (
        "event: message\r\n"
        "id: event-7\r\n"
        "retry: 1250\r\n"
        f"data: {json.dumps(server_request, separators=(',', ':'))}\r\n\r\n"
    ).encode()

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "session-sse"},
                stream=_ChunkStream([event[:19], event[19:37], event[37:]]),
            )
        assert json.loads(request.content)["id"] == "server-7"
        return httpx.Response(
            202,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-sse"},
            content=b"",
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            get_response = await downstream.get(
                "/mcp",
                headers={
                    "Accept": "text/event-stream",
                    "Mcp-Session-Id": "session-sse",
                    "Last-Event-ID": "event-6",
                },
            )
            client_response = await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Mcp-Session-Id": "session-sse"},
                json={"jsonrpc": "2.0", "id": "server-7", "result": {"model": "accepted"}},
            )
            duplicate = await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Mcp-Session-Id": "session-sse"},
                json={"jsonrpc": "2.0", "id": "server-7", "result": {"model": "again"}},
            )
            return app, get_response, client_response, duplicate
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, get_response, client_response, duplicate = anyio.run(exercise)

    assert get_response.status_code == 200
    assert get_response.headers["mcp-session-id"] == "session-sse"
    assert "event: message" in get_response.text
    assert "id: event-7" in get_response.text
    assert "retry: 1250" in get_response.text
    assert json.dumps(server_request, separators=(",", ":")) in get_response.text
    assert calls[0].headers["last-event-id"] == "event-6"
    assert calls[0].headers["mcp-session-id"] == "session-sse"
    assert client_response.status_code == 202
    assert duplicate.status_code == 400
    assert [request.method for request in calls] == ["GET", "POST"]
    assert get_mcp_http_proxy_report(app)["complete"] is False


def test_post_sse_redacts_or_blocks_data_without_losing_event_framing():
    email = "stream@example.com"
    secret = "sk-thisisaverylongfakeapikey222"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        request_id = json.loads(request.content)["id"]
        result = {"email": email} if request_id == 21 else {"token": secret}
        message = {"jsonrpc": "2.0", "id": request_id, "result": result}
        event = (
            "event: message\n"
            f"id: event-{request_id}\n"
            "retry: 500\n"
            f"data: {json.dumps(message, separators=(',', ':'))}\n\n"
        )
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=event.encode(),
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            redacted = await downstream.post("/mcp", headers=POST_HEADERS, json=_request(21))
            blocked = await downstream.post("/mcp", headers=POST_HEADERS, json=_request(22))
            return app, redacted, blocked
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, redacted, blocked = anyio.run(exercise)

    assert redacted.status_code == blocked.status_code == 200
    assert "event: message" in redacted.text
    assert "id: event-21" in redacted.text
    assert "retry: 500" in redacted.text
    assert email not in redacted.text
    assert "<redacted:EMAIL:" in redacted.text
    assert "event: message" in blocked.text
    assert "id: event-22" in blocked.text
    assert "retry: 500" in blocked.text
    assert secret not in blocked.text
    assert "K-Guard blocked an unsafe MCP response" in blocked.text
    assert get_mcp_http_proxy_report(app)["complete"] is True


@pytest.mark.parametrize(
    ("payload", "max_event_bytes", "raw_marker", "expected_kind"),
    [
        (
            b"event: message\nid: bad-json\nretry: 100\ndata: not-json-marker\n\n",
            1024,
            "not-json-marker",
            "malformed_sse_json",
        ),
        (
            b"event: message\ndata: " + b"x" * 180 + b"\n\n",
            96,
            "xxxxxxxxxxxxxxxx",
            "oversized_sse_events",
        ),
        (
            b"event: message\ndata: incomplete-marker",
            1024,
            "incomplete-marker",
            "incomplete_sse_events",
        ),
    ],
)
def test_sse_malformed_oversized_and_incomplete_events_fail_closed(
    payload: bytes,
    max_event_bytes: int,
    raw_marker: str,
    expected_kind: str,
):
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "session-bad"},
            content=payload,
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(
            upstream_handler,
            settings=McpHttpProxySettings(max_sse_event_bytes=max_event_bytes),
        )
        try:
            response = await downstream.get(
                "/mcp",
                headers={"Accept": "text/event-stream", "Mcp-Session-Id": "session-bad"},
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)

    assert response.status_code == 200
    assert raw_marker not in response.text
    assert "K-Guard closed an invalid or unsafe SSE stream" in response.text
    assert report["complete"] is False
    assert expected_kind in {error["kind"] for error in report["control_errors"]}


def test_delete_session_passes_through_and_preserves_status_and_session():
    seen: list[httpx.Request] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-delete"},
            content=b"",
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            return await downstream.delete(
                "/mcp",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2025-11-25",
                    "Mcp-Session-Id": "session-delete",
                    "Origin": "http://127.0.0.1:5173",
                },
            )
        finally:
            await downstream.aclose()
            await upstream.aclose()

    response = anyio.run(exercise)
    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["mcp-session-id"] == "session-delete"
    assert seen[0].method == "DELETE"
    assert seen[0].headers["mcp-session-id"] == "session-delete"
    assert seen[0].headers["mcp-protocol-version"] == "2025-11-25"
    assert "origin" not in seen[0].headers


def test_post_batches_correlate_all_ids_and_reject_duplicate_or_uncorrelated_ids():
    calls = 0

    def good_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json=[
                {"jsonrpc": "2.0", "id": payload[1]["id"], "result": {"order": 2}},
                {"jsonrpc": "2.0", "id": payload[0]["id"], "result": {"order": 1}},
            ],
        )

    async def exercise_good_and_client_duplicate():
        app, upstream, downstream = await _proxy_client(good_handler)
        try:
            good = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json=[_request(1), _request("two")],
            )
            duplicate = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json=[_request(3), _request(3)],
            )
            return good, duplicate
        finally:
            await downstream.aclose()
            await upstream.aclose()

    good, duplicate = anyio.run(exercise_good_and_client_duplicate)
    assert good.status_code == 200
    assert {item["id"] for item in good.json()} == {1, "two"}
    assert duplicate.status_code == 400
    assert calls == 1

    def assert_bad_upstream(bad_ids: list[int]) -> None:
        def bad_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=[
                    {"jsonrpc": "2.0", "id": bad_ids[0], "result": {}},
                    {"jsonrpc": "2.0", "id": bad_ids[1], "result": {}},
                ],
            )

        async def exercise_bad():
            app, upstream, downstream = await _proxy_client(bad_handler)
            try:
                response = await downstream.post(
                    "/mcp",
                    headers=POST_HEADERS,
                    json=[_request(1), _request(2)],
                )
                return app, response
            finally:
                await downstream.aclose()
                await upstream.aclose()

        app, response = anyio.run(exercise_bad)
        assert response.status_code == 502
        assert get_mcp_http_proxy_report(app)["complete"] is False

    assert_bad_upstream([1, 999])
    assert_bad_upstream([1, 1])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"endpoint_path": "/"},
        {"endpoint_path": "mcp"},
        {"endpoint_path": "/mcp?debug=1"},
        {"max_request_bytes": 0},
        {"max_response_bytes": -1},
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
    ],
)
def test_settings_reject_invalid_paths_limits_and_timeouts(kwargs: dict[str, Any]):
    with pytest.raises(ValueError):
        McpHttpProxySettings(**kwargs)


@pytest.mark.parametrize(
    "upstream_url",
    [
        "",
        "ftp://upstream.test/mcp",
        "http://user:password@upstream.test/mcp",
        "http://upstream.test/mcp#fragment",
        "http://upstream.test:invalid/mcp",
    ],
)
def test_proxy_rejects_non_fixed_or_invalid_upstream_urls(upstream_url: str):
    with pytest.raises(ValueError):
        create_mcp_http_proxy_app(upstream_url)


@pytest.mark.parametrize(
    "origin",
    [
        "not-an-origin",
        "http://localhost:invalid",
        "http://user@localhost",
        "http://localhost:80:*",
    ],
)
def test_settings_reject_invalid_origin_patterns(origin: str):
    with pytest.raises(ValueError):
        McpHttpProxySettings(allowed_origins=(origin,))


def test_toolchain_contract_is_current_and_fails_closed_when_a_source_is_unreadable(monkeypatch: pytest.MonkeyPatch):
    current = proxy_module.mcp_http_proxy_toolchain_contract()
    assert current["complete"] is True
    assert current["hashed_file_count"] == current["expected_file_count"] == 9
    assert len(current["sha256"]) == 64

    original_read_bytes = Path.read_bytes

    def fail_one_source(path: Path) -> bytes:
        if path.name == "mcp_runtime.py":
            raise OSError("synthetic unreadable source")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_one_source)
    incomplete = proxy_module.mcp_http_proxy_toolchain_contract()
    assert incomplete["complete"] is False
    assert incomplete["hashed_file_count"] == incomplete["expected_file_count"] - 1
    assert incomplete["sha256"] != current["sha256"]


def test_report_accessor_rejects_unrelated_apps_and_owned_client_closes_on_lifespan():
    with pytest.raises(ValueError, match="not a K-Guard"):
        get_mcp_http_proxy_report(Starlette())

    async def exercise() -> bool:
        app = create_mcp_http_proxy_app("http://upstream.test/mcp")
        client = _proxy_for(app).client
        async with app.router.lifespan_context(app):
            assert client.is_closed is False
        return client.is_closed

    assert anyio.run(exercise) is True


@pytest.mark.parametrize(
    ("content_type", "body", "expected_status", "expected_code"),
    [
        ("text/plain", json.dumps(_request()).encode(), 415, -32600),
        ("application/json", b"", 400, -32700),
        ("application/json", b"{", 400, -32700),
        (
            "application/json",
            b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{}}',
            400,
            -32700,
        ),
        (
            "application/json",
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"value":NaN}}',
            400,
            -32700,
        ),
        ("application/json", b"\xff", 400, -32700),
        ("application/json", b"[]", 400, -32600),
        ("application/json", b"[1]", 400, -32600),
        ("application/json", b'{"jsonrpc":"2.0","id":true,"method":"tools/call"}', 400, -32600),
        ("application/json", b'{"jsonrpc":"2.0","id":1}', 400, -32600),
    ],
)
def test_malformed_duplicate_nonfinite_and_invalid_client_json_never_reaches_upstream(
    content_type: str,
    body: bytes,
    expected_status: int,
    expected_code: int,
):
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post(
                "/mcp",
                headers={"Accept": POST_HEADERS["Accept"], "Content-Type": content_type},
                content=body,
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    assert response.json()["error"]["data"]["raw_content_forwarded"] is False
    assert calls == 0
    assert report["passed"] is False


@pytest.mark.parametrize(
    ("method", "headers", "messages", "settings", "expected_status", "counter"),
    [
        (
            "POST",
            [
                (b"content-type", b"application/json"),
                (b"origin", b"http://localhost:1"),
                (b"origin", b"http://localhost:2"),
            ],
            None,
            McpHttpProxySettings(),
            403,
            "origin_rejections",
        ),
        (
            "POST",
            [(b"content-type", b"application/json"), (b"mcp-session-id", b"a"), (b"mcp-session-id", b"b")],
            None,
            McpHttpProxySettings(),
            400,
            "duplicate_transport_headers",
        ),
        (
            "POST",
            [(b"content-type", b"application/json")],
            None,
            McpHttpProxySettings(max_transport_header_bytes=8),
            431,
            "oversized_transport_headers",
        ),
        (
            "POST",
            [(b"content-type", b"application/json"), (b"accept", b"application/json\ninvalid")],
            None,
            McpHttpProxySettings(),
            400,
            "invalid_transport_headers",
        ),
        (
            "POST",
            [(b"content-type", b"application/json"), (b"content-length", b"1"), (b"content-length", b"1")],
            None,
            McpHttpProxySettings(),
            400,
            "duplicate_content_length",
        ),
        (
            "POST",
            [(b"content-type", b"application/json"), (b"content-length", b"invalid")],
            None,
            McpHttpProxySettings(),
            400,
            "invalid_content_length",
        ),
        (
            "POST",
            [(b"content-type", b"application/json"), (b"content-length", b"-1")],
            None,
            McpHttpProxySettings(),
            400,
            "invalid_content_length",
        ),
        (
            "GET",
            [],
            [{"type": "http.request", "body": b"unexpected", "more_body": False}],
            McpHttpProxySettings(),
            400,
            "unexpected_request_body",
        ),
    ],
)
def test_raw_asgi_transport_header_and_body_controls_fail_before_upstream(
    method: str,
    headers: list[tuple[bytes, bytes]],
    messages: list[dict[str, Any]] | None,
    settings: McpHttpProxySettings,
    expected_status: int,
    counter: str,
):
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        app = create_mcp_http_proxy_app("http://upstream.test/mcp", settings, http_client=upstream)
        try:
            result = await _raw_asgi_exchange(app, method=method, headers=headers, messages=messages)
            return app, result
        finally:
            await upstream.aclose()

    app, (status, _, body) = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert status == expected_status
    assert json.loads(body)["error"]["data"]["raw_content_forwarded"] is False
    assert calls == 0
    assert report["counts"][counter] == 1


def test_method_rejection_stream_limit_timeout_and_disconnect_are_fail_closed():
    async def exercise():
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500)))
        app = create_mcp_http_proxy_app(
            "http://upstream.test/mcp",
            McpHttpProxySettings(max_request_bytes=32, timeout_seconds=0.01),
            http_client=upstream,
        )

        async def slow_receive() -> dict[str, Any]:
            await anyio.sleep(0.1)
            return {"type": "http.request", "body": b"", "more_body": False}

        try:
            method = await _raw_asgi_exchange(app, method="PATCH")
            oversized = await _raw_asgi_exchange(
                app,
                method="POST",
                headers=[(b"content-type", b"application/json")],
                messages=[
                    {"type": "http.request", "body": b"x" * 64, "more_body": True},
                    {"type": "http.request", "body": b"", "more_body": False},
                ],
            )
            timeout = await _raw_asgi_exchange(
                app,
                method="POST",
                headers=[(b"content-type", b"application/json")],
                receive=slow_receive,
            )
            disconnect = await _raw_asgi_exchange(
                app,
                method="POST",
                headers=[(b"content-type", b"application/json")],
                messages=[{"type": "http.disconnect"}],
            )
            return app, method, oversized, timeout, disconnect
        finally:
            await upstream.aclose()

    app, method, oversized, timeout, disconnect = anyio.run(exercise)
    assert [item[0] for item in (method, oversized, timeout, disconnect)] == [405, 413, 408, 400]
    assert dict(method[1])[b"allow"] == b"GET, POST, DELETE"
    counts = get_mcp_http_proxy_report(app)["counts"]
    assert counts["method_rejections"] == 1
    assert counts["oversized_requests"] == 1
    assert counts["request_body_timeouts"] == 1
    assert counts["request_body_disconnects"] == 1


def test_malformed_origin_is_rejected_without_leaking_or_forwarding():
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Origin": "not-an-origin"},
                json=_request(),
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    assert response.status_code == 403
    assert calls == 0
    assert get_mcp_http_proxy_report(app)["counts"]["origin_rejections"] == 1


def test_report_write_failure_and_nonstandard_findings_fail_closed_without_raw_values(tmp_path: Path):
    report_target = tmp_path / "report.json"
    report_target.mkdir()
    app = create_mcp_http_proxy_app(
        "http://upstream.test/mcp",
        McpHttpProxySettings(report_path=report_target),
    )
    recorder = app.state.k_guard_proxy_reporter
    sensitive = "raw-value-must-not-survive"
    recorder.add_findings([{"rule_id": "TEST-DICT", "raw_returned": False}, sensitive])
    recorder.publish()

    report = get_mcp_http_proxy_report(app)
    assert report["complete"] is False
    assert report["passed"] is False
    assert report["control_status"] == "failed_closed"
    assert {item["kind"] for item in report["control_errors"]} == {"report_write_errors"}
    assert report["finding_count"] == 2
    assert sensitive not in json.dumps(report)
    assert verify_evidence_bundle(report["evidence_bundle"]) is True


@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.RemoteProtocolError])
def test_upstream_network_and_protocol_errors_fail_closed(error_type: type[httpx.HTTPError]):
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        raise error_type("synthetic upstream failure", request=request)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == 502
    assert response.json()["error"]["message"] == "Upstream request failed"
    assert {item["kind"] for item in report["control_errors"]} == {"upstream_connection_errors"}


def _upstream_response(case: str, request: httpx.Request) -> httpx.Response:
    valid = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
    if case == "redirect_without_location":
        return httpx.Response(302, request=request)
    if case == "session_mismatch":
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-b"},
            content=valid,
            request=request,
        )
    if case == "delete_sse":
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=b"event: ping\n\n",
            request=request,
        )
    if case == "unsupported_content_type":
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"not-json", request=request)
    if case == "malformed_json":
        return httpx.Response(200, headers={"Content-Type": "application/json"}, content=b"{", request=request)
    if case == "duplicate_json_key":
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b'{"jsonrpc":"2.0","id":1,"id":2,"result":{}}',
            request=request,
        )
    if case == "nonfinite_json":
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b'{"jsonrpc":"2.0","id":1,"result":{"score":Infinity}}',
            request=request,
        )
    if case == "invalid_jsonrpc":
        return httpx.Response(200, headers={"Content-Type": "application/json"}, json={"id": 1}, request=request)
    if case == "empty_expected_response":
        return httpx.Response(200, headers={"Content-Type": "application/json"}, content=b"", request=request)
    if case == "notification_missing_expected_response":
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
            request=request,
        )
    if case == "duplicate_session_header":
        return httpx.Response(
            200,
            headers=[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "session-a"),
                ("Mcp-Session-Id", "session-a"),
            ],
            content=valid,
            request=request,
        )
    if case == "invalid_session_header":
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a,session-b"},
            content=valid,
            request=request,
        )
    raise AssertionError(f"unknown test case: {case}")


@pytest.mark.parametrize(
    ("case", "method", "session_id", "expected_kind"),
    [
        ("redirect_without_location", "POST", None, "upstream_redirects_blocked"),
        ("session_mismatch", "POST", "session-a", "upstream_session_mismatches"),
        ("delete_sse", "DELETE", None, "unexpected_sse_responses"),
        ("unsupported_content_type", "POST", None, "unsupported_upstream_content_types"),
        ("malformed_json", "POST", None, "malformed_upstream_json"),
        ("duplicate_json_key", "POST", None, "malformed_upstream_json"),
        ("nonfinite_json", "POST", None, "malformed_upstream_json"),
        ("invalid_jsonrpc", "POST", None, "malformed_upstream_json"),
        ("empty_expected_response", "POST", None, "missing_upstream_responses"),
        ("notification_missing_expected_response", "POST", None, "missing_upstream_responses"),
        ("duplicate_session_header", "POST", None, "duplicate_upstream_session_headers"),
        ("invalid_session_header", "POST", None, "invalid_upstream_session_headers"),
    ],
)
def test_upstream_response_protocol_and_lifecycle_failures_are_rejected(
    case: str,
    method: str,
    session_id: str | None,
    expected_kind: str,
):
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return _upstream_response(case, request)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        headers = dict(POST_HEADERS)
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        try:
            if method == "POST":
                response = await downstream.post("/mcp", headers=headers, json=_request())
            else:
                response = await downstream.delete("/mcp", headers=headers)
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == 502
    assert response.json()["error"]["data"]["raw_content_forwarded"] is False
    assert expected_kind in {item["kind"] for item in report["control_errors"]}
    assert report["complete"] is False


@pytest.mark.parametrize(
    ("headers", "stream", "settings", "expected_status", "expected_kind"),
    [
        (
            {"Content-Type": "application/json", "Content-Length": "invalid"},
            _ChunkStream([b"{}"]),
            McpHttpProxySettings(),
            502,
            "invalid_upstream_content_lengths",
        ),
        (
            {"Content-Type": "application/json", "Content-Length": "-1"},
            _ChunkStream([b"{}"]),
            McpHttpProxySettings(),
            502,
            "invalid_upstream_content_lengths",
        ),
        (
            {"Content-Type": "application/json", "Content-Length": "512"},
            _ChunkStream([b"{}"]),
            McpHttpProxySettings(max_response_bytes=64),
            502,
            "oversized_upstream_responses",
        ),
        (
            {"Content-Type": "application/json"},
            _ChunkStream([b"x" * 80]),
            McpHttpProxySettings(max_response_bytes=64),
            502,
            "oversized_upstream_responses",
        ),
        (
            {"Content-Type": "application/json"},
            _DelayedChunkStream(b'{"jsonrpc":"2.0","id":1,"result":{}}'),
            McpHttpProxySettings(timeout_seconds=0.01),
            504,
            "upstream_timeouts",
        ),
    ],
)
def test_upstream_response_length_stream_size_and_read_timeout_controls(
    headers: dict[str, str],
    stream: httpx.AsyncByteStream,
    settings: McpHttpProxySettings,
    expected_status: int,
    expected_kind: str,
):
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers, stream=stream, request=request)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler, settings=settings)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == expected_status
    assert expected_kind in {item["kind"] for item in report["control_errors"]}
    assert report["complete"] is False


def test_fully_blocked_json_response_is_not_forwarded(monkeypatch: pytest.MonkeyPatch):
    raw_marker = "server-block-marker"

    async def block_upstream(self: Any, message: dict[str, Any], **kwargs: Any):
        return None, "block", []

    monkeypatch.setattr(proxy_module._RuntimePolicy, "inspect_upstream", block_upstream)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "result": {"marker": raw_marker}},
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report_text = json.dumps(get_mcp_http_proxy_report(app))
    assert response.status_code == 502
    assert raw_marker not in response.text
    assert raw_marker not in report_text
    assert "fully_blocked_upstream_payloads" in report_text


@pytest.mark.parametrize(
    ("direction", "failure_mode", "expected_kind", "expected_status"),
    [
        ("client", "exception", "client_policy_control_errors", 500),
        ("client", "invalid_action", "invalid_client_policy_actions", 500),
        ("upstream", "exception", "upstream_policy_control_errors", 500),
        ("upstream", "invalid_action", "invalid_upstream_policy_actions", 500),
    ],
)
def test_policy_engine_exception_and_invalid_action_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
    failure_mode: str,
    expected_kind: str,
    expected_status: int,
):
    if direction == "client":
        def client_policy(observer: Any, message: dict[str, Any]):
            if failure_mode == "exception":
                raise RuntimeError("synthetic client policy failure")
            return [], message, "invalid-action", []

        monkeypatch.setattr(proxy_module._stdio_proxy, "_enforce_client_message", client_policy)
    else:
        def upstream_policy(observer: Any, message: dict[str, Any], *, is_response: bool):
            if failure_mode == "exception":
                raise RuntimeError("synthetic upstream policy failure")
            return SimpleNamespace(findings=[]), message, "invalid-action"

        monkeypatch.setattr(proxy_module._stdio_proxy, "_enforce_upstream_message", upstream_policy)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == expected_status
    assert {item["kind"] for item in report["control_errors"]} == {expected_kind}
    assert report["passed"] is False


def test_lifecycle_registry_enforces_session_pending_and_reservation_invariants():
    async def exercise() -> None:
        registry = proxy_module._LifecycleRegistry(max_sessions=1, max_pending_per_session=1)
        await registry.register_server_requests(None, [])

        with pytest.raises(proxy_module._LifecycleViolation) as duplicate_batch:
            await registry.register_server_requests("session-a", ["id-1", "id-1"])
        assert duplicate_batch.value.kind == "duplicate_upstream_request_ids"

        with pytest.raises(proxy_module._LifecycleViolation) as no_session:
            await registry.register_server_requests(None, ["id-1"])
        assert no_session.value.kind == "uncorrelatable_server_requests"

        await registry.register_server_requests("session-a", ["id-1"])
        with pytest.raises(proxy_module._LifecycleViolation) as outstanding_duplicate:
            await registry.register_server_requests("session-a", ["id-1"])
        assert outstanding_duplicate.value.kind == "duplicate_upstream_request_ids"

        with pytest.raises(proxy_module._LifecycleViolation) as pending_capacity:
            await registry.register_server_requests("session-a", ["id-2"])
        assert pending_capacity.value.kind == "lifecycle_request_capacity_exceeded"

        with pytest.raises(proxy_module._LifecycleViolation) as session_capacity:
            await registry.register_server_requests("session-b", ["id-2"])
        assert session_capacity.value.kind == "lifecycle_session_capacity_exceeded"

        with pytest.raises(proxy_module._LifecycleViolation) as response_without_session:
            await registry.reserve_client_responses(None, {"id-1"})
        assert response_without_session.value.kind == "uncorrelated_client_responses"

        with pytest.raises(proxy_module._LifecycleViolation) as response_without_request:
            await registry.reserve_client_responses("session-a", {"unknown"})
        assert response_without_request.value.kind == "uncorrelated_client_responses"

        reservation = await registry.reserve_client_responses("session-a", {"id-1"})
        assert reservation is not None
        with pytest.raises(proxy_module._LifecycleViolation) as double_reservation:
            await registry.reserve_client_responses("session-a", {"id-1"})
        assert double_reservation.value.kind == "uncorrelated_client_responses"

        await reservation.release()
        await reservation.release()
        retry = await registry.reserve_client_responses("session-a", {"id-1"})
        assert retry is not None
        await retry.commit()
        await retry.commit()
        assert await registry.pending_count() == 0

        orphan = proxy_module._Reservation(registry, "missing", frozenset({"id"}), "token")
        await registry.settle(orphan, commit=True)
        await registry.register_server_requests("session-a", ["id-3"])
        mismatched = proxy_module._Reservation(registry, "session-a", frozenset({"id-3"}), "wrong-token")
        await registry.settle(mismatched, commit=True)
        assert await registry.clear_session("session-a") == 1

    anyio.run(exercise)


def test_finalize_and_session_clear_record_unanswered_and_cancelled_requests():
    async def exercise():
        app = create_mcp_http_proxy_app("http://upstream.test/mcp")
        proxy = _proxy_for(app)
        try:
            await proxy.lifecycle.register_server_requests("session-a", ["id-1", "id-2"])
            await proxy._clear_session("session-a")
            await proxy.lifecycle.register_server_requests("session-b", ["id-3"])
            await proxy.finalize()
            return app
        finally:
            await proxy.client.aclose()

    app = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert report["counts"]["sessions_deleted"] == 1
    assert report["counts"]["pending_server_requests_cancelled"] == 2
    assert {item["kind"] for item in report["control_errors"]} == {"unanswered_server_requests"}


def test_notification_only_policy_block_returns_safe_error_without_upstream_call():
    calls = 0
    secret = "sk-thisisaverylongfakeapikey-notification"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"token": secret}},
                },
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report_text = json.dumps(get_mcp_http_proxy_report(app))
    assert response.status_code == 403
    assert response.json()["id"] is None
    assert calls == 0
    assert secret not in response.text
    assert secret not in report_text


def test_post_correlates_server_request_then_releases_failed_client_response_for_retry():
    calls = 0

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        if calls == 1:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a"},
                json=[
                    {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}},
                    {
                        "jsonrpc": "2.0",
                        "id": "server-1",
                        "method": "sampling/createMessage",
                        "params": {"messages": []},
                    },
                ],
            )
        if calls == 2:
            return httpx.Response(
                500,
                headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a"},
                content=b"",
            )
        return httpx.Response(
            202,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a"},
            content=b"",
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            first = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            client_response = {"jsonrpc": "2.0", "id": "server-1", "result": {"accepted": True}}
            failed = await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Mcp-Session-Id": "session-a"},
                json=client_response,
            )
            retry = await downstream.post(
                "/mcp",
                headers={**POST_HEADERS, "Mcp-Session-Id": "session-a"},
                json=client_response,
            )
            return app, first, failed, retry
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, first, failed, retry = anyio.run(exercise)
    assert first.status_code == 200
    assert failed.status_code == 500
    assert retry.status_code == 202
    assert calls == 3
    assert get_mcp_http_proxy_report(app)["counts"]["server_requests_correlated"] == 1


def test_duplicate_server_request_in_post_response_is_a_lifecycle_failure():
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        server_request = {
            "jsonrpc": "2.0",
            "id": "server-duplicate",
            "method": "sampling/createMessage",
            "params": {"messages": []},
        }
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Mcp-Session-Id": "session-a"},
            json=[
                {"jsonrpc": "2.0", "id": payload["id"], "result": {}},
                server_request,
                server_request,
            ],
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    assert response.status_code == 502
    assert {item["kind"] for item in get_mcp_http_proxy_report(app)["control_errors"]} == {
        "duplicate_upstream_request_ids"
    }


@pytest.mark.parametrize(
    ("stream", "settings", "expected_kind"),
    [
        (
            _DelayedChunkStream(b"event: ping\n\n"),
            McpHttpProxySettings(timeout_seconds=0.01),
            "sse_upstream_timeouts",
        ),
        (
            _FailingChunkStream(httpx.ReadError("synthetic SSE read error")),
            McpHttpProxySettings(),
            "sse_upstream_errors",
        ),
        (
            _FailingChunkStream(RuntimeError("synthetic SSE control error")),
            McpHttpProxySettings(),
            "unexpected_sse_control_error",
        ),
    ],
)
def test_sse_timeout_network_and_unexpected_stream_errors_emit_fail_closed_event(
    stream: httpx.AsyncByteStream,
    settings: McpHttpProxySettings,
    expected_kind: str,
):
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=stream,
            request=request,
        )

    async def exercise():
        app, upstream, downstream = await _proxy_client(upstream_handler, settings=settings)
        try:
            response = await downstream.get("/mcp", headers={"Accept": "text/event-stream"})
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code == 200
    assert "K-Guard closed an invalid or unsafe SSE stream" in response.text
    assert expected_kind in {item["kind"] for item in report["control_errors"]}
    assert report["complete"] is False


def test_sse_policy_failure_is_closed_and_control_and_blocked_events_are_counted(monkeypatch: pytest.MonkeyPatch):
    notification = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"marker": "blocked-marker"}}
    payload = b"event: ping\n\n" + (
        "event: message\n" + f"data: {json.dumps(notification, separators=(',', ':'))}\n\n"
    ).encode()

    async def block_upstream(self: Any, message: dict[str, Any], **kwargs: Any):
        return None, "block", []

    monkeypatch.setattr(proxy_module._RuntimePolicy, "inspect_upstream", block_upstream)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, content=payload)

    async def exercise_blocked():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.get("/mcp", headers={"Accept": "text/event-stream"})
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    blocked_app, blocked_response = anyio.run(exercise_blocked)
    blocked_report = get_mcp_http_proxy_report(blocked_app)
    assert blocked_response.text == "event: ping\n\n"
    assert blocked_report["counts"]["sse_control_events_forwarded"] == 1
    assert blocked_report["counts"]["sse_events_blocked"] == 1

    async def fail_policy(self: Any, message: dict[str, Any], **kwargs: Any):
        raise proxy_module._PolicyControlFailure("synthetic_sse_policy_failure", "synthetic")

    monkeypatch.setattr(proxy_module._RuntimePolicy, "inspect_upstream", fail_policy)

    async def exercise_failure():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.get("/mcp", headers={"Accept": "text/event-stream"})
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    failed_app, failed_response = anyio.run(exercise_failure)
    assert "K-Guard closed an invalid or unsafe SSE stream" in failed_response.text
    assert {item["kind"] for item in get_mcp_http_proxy_report(failed_app)["control_errors"]} == {
        "synthetic_sse_policy_failure"
    }


def test_post_sse_missing_response_and_downstream_early_close_are_recorded():
    notification = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
    event = f"data: {json.dumps(notification, separators=(',', ':'))}\n\n".encode()

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, content=event)

    async def exercise_post():
        app, upstream, downstream = await _proxy_client(upstream_handler)
        try:
            response = await downstream.post("/mcp", headers=POST_HEADERS, json=_request())
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    post_app, post_response = anyio.run(exercise_post)
    assert "K-Guard closed an invalid or unsafe SSE stream" in post_response.text
    assert {item["kind"] for item in get_mcp_http_proxy_report(post_app)["control_errors"]} == {
        "missing_upstream_responses"
    }

    async def exercise_early_close():
        app = create_mcp_http_proxy_app("http://upstream.test/mcp")
        proxy = _proxy_for(app)
        response = httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=_ChunkStream([event]),
            request=httpx.Request("POST", "http://upstream.test/mcp"),
        )
        lifecycle = proxy_module._PostLifecycle(expected_responses={"1": "tools/call"})
        iterator = proxy._stream_sse(response, lifecycle, None)
        try:
            assert await iterator.__anext__() == event
            await iterator.aclose()
            return app
        finally:
            await proxy.client.aclose()

    early_app = anyio.run(exercise_early_close)
    assert {item["kind"] for item in get_mcp_http_proxy_report(early_app)["control_errors"]} == {
        "incomplete_downstream_sse_delivery"
    }


def test_sse_parser_handles_bom_cr_comments_empty_data_and_rejects_utf8_and_event_overflow():
    parser = proxy_module._IncrementalSSEParser(128)
    assert list(parser.feed(b"\xef\xbb\xbf: comment\rdata: \r")) == []
    events = list(parser.feed(b"\n\r\n"))
    assert len(events) == 1
    assert events[0].data == ""
    parser.finish()

    invalid_utf8 = proxy_module._IncrementalSSEParser(128)
    with pytest.raises(proxy_module._MalformedSSE) as utf8_error:
        list(invalid_utf8.feed(b"data: \xff\n\n"))
    assert utf8_error.value.kind == "malformed_sse_utf8"

    oversized = proxy_module._IncrementalSSEParser(8)
    with pytest.raises(proxy_module._MalformedSSE) as size_error:
        list(oversized.feed(b"data:123456\n\n"))
    assert size_error.value.kind == "oversized_sse_events"

    no_data_line = proxy_module._SSEEvent(raw=b"event: ping\n\n", lines=("event: ping",), data=None)
    assert no_data_line.replace_data("{}") == b"event: ping\ndata: {}\n\n"


def test_policy_transform_and_protocol_version_helpers_preserve_rpc_identity():
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}
    cases = [
        "not-an-object",
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {**request, "id": 2},
        {**request, "method": "resources/read"},
    ]
    for transformed in cases:
        with pytest.raises(proxy_module._PolicyControlFailure) as failure:
            proxy_module._validate_policy_transform(request, transformed)
        assert failure.value.kind == "invalid_policy_transforms"

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"},
    }
    shielded, version = proxy_module._shield_protocol_version(initialize, method="initialize")
    assert version == "2025-11-25"
    assert shielded["params"]["protocolVersion"] == proxy_module._PROTOCOL_VERSION_PLACEHOLDER
    assert proxy_module._restore_protocol_version(shielded, "params", version) == initialize
    assert proxy_module._shield_protocol_version({**initialize, "params": []}, method="initialize") == (
        {**initialize, "params": []},
        None,
    )
    assert proxy_module._shield_protocol_version(
        {**initialize, "params": {"protocolVersion": "not-a-date"}}, method="initialize"
    )[1] is None
    assert proxy_module._restore_protocol_version(initialize, "params", version) == initialize
    assert proxy_module._is_protocol_date("2025-1-01") is False
    assert proxy_module._is_protocol_date("2025-99-99") is False
    assert proxy_module._strict_rpc_id(True) is False


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
            target=self.server.run,
            kwargs={"sockets": [self.socket]},
            name=f"test-uvicorn-{self.port}",
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self.server.started:
            self.close()
            raise RuntimeError("uvicorn test server did not start")

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self.socket.fileno() != -1:
            self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError("uvicorn test server did not stop")


def test_official_sdk_interoperates_with_fastmcp_streamable_http_app():
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.fastmcp import FastMCP

    upstream_mcp = FastMCP("official-upstream", log_level="ERROR")

    @upstream_mcp.tool()
    def echo(text: str) -> str:
        return f"echo:{text}"

    upstream_server = _RunningUvicorn(upstream_mcp.streamable_http_app())
    proxy_app = create_mcp_http_proxy_app(
        f"http://127.0.0.1:{upstream_server.port}/mcp",
        McpHttpProxySettings(timeout_seconds=5),
    )
    proxy_server = _RunningUvicorn(proxy_app)

    async def exercise():
        async with streamable_http_client(
            f"http://127.0.0.1:{proxy_server.port}/mcp"
        ) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("echo", {"text": "hello"})
                return initialized, tools, result, get_session_id()

    try:
        initialized, tools, result, session_id = anyio.run(exercise)
        report = get_mcp_http_proxy_report(proxy_app)
    finally:
        proxy_server.close()
        upstream_server.close()

    assert initialized.serverInfo.name == "official-upstream"
    assert session_id
    assert {tool.name for tool in tools.tools} == {"echo"}
    assert result.content[0].text == "echo:hello"
    assert report["transport"] == "streamable_http"
    assert report["complete"] is True
    assert report["counts"]["requests_post"] >= 4
    assert report["counts"]["requests_get"] >= 1
    assert report["counts"]["requests_delete"] == 1
