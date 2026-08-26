from __future__ import annotations

import asyncio
import hashlib
import json
import math
import secrets
import threading
import time
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator
from urllib.parse import urlsplit

import anyio
import httpx
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from k_guard_mcp.access_policy import AccessPolicyController
from k_guard_mcp import mcp_proxy as _stdio_proxy
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.mcp_runtime import McpRuntimeObserver
from k_guard_mcp.provenance import evidence_bundle, object_artifact
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.runtime_mediation_receipts import (
    RuntimeMediationReceiptChain,
    RuntimeMediationReceiptError,
    forwarding_contract,
    new_transaction_id,
    policy_ref_for,
    receipt_persist_path_for_report,
)


DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:*",
    "https://localhost:*",
    "http://127.0.0.1:*",
    "https://127.0.0.1:*",
    "http://[::1]:*",
    "https://[::1]:*",
)


def mcp_http_proxy_toolchain_contract() -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    paths = [
        package_root / "access_policy.py",
        package_root / "mcp_http_proxy.py",
        package_root / "mcp_proxy.py",
        package_root / "mcp_runtime.py",
        package_root / "redaction.py",
        package_root / "runtime_validation.py",
        package_root / "hashing.py",
        package_root / "detectors" / "mcp_threat.py",
        package_root / "runtime_mediation_receipts.py",
    ]
    digest = hashlib.sha256()
    hashed = 0
    for path in paths:
        try:
            relative = path.relative_to(package_root).as_posix().encode("utf-8")
            content = path.read_bytes()
        except (OSError, ValueError):
            continue
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        hashed += 1
    return {
        "schema": "k_guard_mcp_http_proxy_toolchain.v1",
        "sha256": digest.hexdigest(),
        "expected_file_count": len(paths),
        "hashed_file_count": hashed,
        "complete": hashed == len(paths),
        "raw_returned": False,
    }

_REQUEST_HEADER_ALLOWLIST = {
    "accept": "Accept",
    "content-type": "Content-Type",
    "mcp-protocol-version": "MCP-Protocol-Version",
    "mcp-session-id": "Mcp-Session-Id",
    "last-event-id": "Last-Event-ID",
    "authorization": "Authorization",
}
_SINGLETON_REQUEST_HEADERS = frozenset(_REQUEST_HEADER_ALLOWLIST) - {"accept"}
_JSON = "application/json"
_SSE = "text/event-stream"
_PROTOCOL_VERSION_PLACEHOLDER = "mcp-negotiated-version"


@dataclass(frozen=True, slots=True)
class McpHttpProxySettings:
    endpoint_path: str = "/mcp"
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    max_request_bytes: int = 1024 * 1024
    max_response_bytes: int = 4 * 1024 * 1024
    max_sse_event_bytes: int = 1024 * 1024
    max_sse_stream_bytes: int = 16 * 1024 * 1024
    max_sse_events: int = 10_000
    max_sse_stream_seconds: float = 300.0
    max_concurrent_sse_streams: int = 32
    max_transport_header_bytes: int = 16 * 1024
    timeout_seconds: float = 30.0
    forward_authorization: bool = False
    require_origin: bool = False
    fail_closed_on_report_error: bool = True
    max_lifecycle_sessions: int = 256
    max_pending_server_requests_per_session: int = 256
    report_path: str | Path | None = None
    receipt_log_path: str | Path | None = None

    def __post_init__(self) -> None:
        origins = tuple(str(item) for item in self.allowed_origins)
        object.__setattr__(self, "allowed_origins", origins)
        if not self.endpoint_path.startswith("/") or self.endpoint_path == "/":
            raise ValueError("endpoint_path must be one non-root absolute path")
        if "{" in self.endpoint_path or "}" in self.endpoint_path or "?" in self.endpoint_path:
            raise ValueError("endpoint_path must be a fixed path")
        for name in (
            "max_request_bytes",
            "max_response_bytes",
            "max_sse_event_bytes",
            "max_sse_stream_bytes",
            "max_sse_events",
            "max_concurrent_sse_streams",
            "max_transport_header_bytes",
            "max_lifecycle_sessions",
            "max_pending_server_requests_per_session",
        ):
            if int(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")
        if not math.isfinite(float(self.timeout_seconds)) or float(self.timeout_seconds) <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        if not math.isfinite(float(self.max_sse_stream_seconds)) or float(self.max_sse_stream_seconds) <= 0:
            raise ValueError("max_sse_stream_seconds must be a positive finite number")
        for origin in origins:
            _parse_origin_pattern(origin)


def create_mcp_http_proxy_app(
    upstream_url: str,
    settings: McpHttpProxySettings | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
    access_controller: AccessPolicyController | None = None,
) -> Starlette:
    """Create a single-endpoint Streamable HTTP MCP reverse proxy."""
    policy = settings or McpHttpProxySettings()
    if access_controller is not None and policy.forward_authorization:
        raise ValueError("access grant Authorization headers must not be forwarded upstream")
    fixed_upstream = _validate_upstream_url(upstream_url)
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(policy.timeout_seconds),
        headers={},
    )
    recorder = _ReportRecorder(fixed_upstream, policy, access_controller=access_controller)
    proxy = _McpHttpProxy(fixed_upstream, policy, client, recorder, access_controller=access_controller)
    endpoint = _ProxyASGIEndpoint(proxy)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await proxy.finalize()
            if owns_client:
                await client.aclose()
            recorder.publish()

    app = Starlette(
        routes=[Route(policy.endpoint_path, endpoint=endpoint)],
        lifespan=lifespan,
    )
    app.router.redirect_slashes = False
    recorder.attach_app(app)
    recorder.publish()
    return app


def get_mcp_http_proxy_report(app: Starlette) -> dict[str, Any]:
    reporter = getattr(app.state, "k_guard_proxy_reporter", None)
    if not isinstance(reporter, _ReportRecorder):
        raise ValueError("app is not a K-Guard MCP HTTP proxy")
    return reporter.snapshot()


create_app = create_mcp_http_proxy_app


class _ProxyASGIEndpoint:
    def __init__(self, proxy: _McpHttpProxy) -> None:
        self.proxy = proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        if request.method not in {"POST", "GET", "DELETE"}:
            self.proxy.recorder.count("method_rejections")
            response = _rpc_error_response(
                405,
                -32600,
                "Method Not Allowed",
                headers={"Allow": "GET, POST, DELETE"},
            )
            self.proxy.recorder.publish()
        else:
            response = await self.proxy.handle(request)
        await response(scope, receive, send)


class _McpHttpProxy:
    def __init__(
        self,
        upstream_url: str,
        settings: McpHttpProxySettings,
        client: httpx.AsyncClient,
        recorder: _ReportRecorder,
        access_controller: AccessPolicyController | None = None,
    ) -> None:
        self.upstream_url = upstream_url
        self.settings = settings
        self.client = client
        self.recorder = recorder
        self.access_controller = access_controller
        self.policy = _RuntimePolicy(recorder)
        self.lifecycle = _LifecycleRegistry(
            settings.max_lifecycle_sessions,
            settings.max_pending_server_requests_per_session,
        )
        self._sse_lock = asyncio.Lock()
        self._active_sse_streams = 0

    async def handle(self, request: Request) -> Response:
        self.recorder.count("requests_total")
        self.recorder.count(f"requests_{request.method.lower()}")
        if self.settings.fail_closed_on_report_error and self.recorder.report_write_failed:
            self.recorder.count("report_persistence_rejections")
            return _rpc_error_response(503, -32603, "K-Guard audit persistence is unavailable")
        try:
            self._validate_origin(request)
            access_token, principal_ref = self._authenticate_request(request)
            headers = self._forward_headers(request)
            body = await self._read_request_body(request)
            if request.method != "POST" and body:
                raise _RequestProblem(400, "unexpected_request_body", "GET and DELETE requests must not have a body")
            if request.method == "POST":
                response = await self._handle_post(
                    request,
                    headers,
                    body,
                    access_token=access_token,
                    principal_ref=principal_ref,
                )
            else:
                self._authorize_transport_method(request.method, access_token)
                response = await self._forward(
                    request.method,
                    headers,
                    None,
                    incoming_session=headers.get("Mcp-Session-Id"),
                    post_lifecycle=None,
                    reservation=None,
                    access_token=access_token,
                    principal_ref=principal_ref,
                )
        except _RequestProblem as exc:
            self.recorder.count(exc.kind)
            response = _rpc_error_response(exc.status_code, exc.rpc_code, exc.safe_message)
        except _PolicyControlFailure as exc:
            self.recorder.control_error(exc.kind, exc)
            response = _rpc_error_response(500, -32603, "K-Guard policy control failed closed")
        except _LifecycleViolation as exc:
            self.recorder.control_error(exc.kind, exc)
            response = _rpc_error_response(400, -32600, "K-Guard rejected an invalid JSON-RPC lifecycle")
        except Exception as exc:
            self.recorder.control_error("unexpected_proxy_control_error", exc)
            response = _rpc_error_response(500, -32603, "K-Guard proxy control failed closed")
        self.recorder.publish()
        return response

    def _authenticate_request(self, request: Request) -> tuple[str | None, str]:
        if self.access_controller is None:
            return None, evidence_hash("anonymous-http-principal")
        values = _raw_header_values(request, "authorization")
        if len(values) != 1:
            raise _RequestProblem(401, "access_authentication_rejections", "A single Bearer grant is required", -32003)
        scheme, separator, token = values[0].partition(" ")
        if not separator or scheme.casefold() != "bearer" or not token or token != token.strip():
            raise _RequestProblem(401, "access_authentication_rejections", "A valid Bearer grant is required", -32003)
        decision = self.access_controller.authenticate_grant(token)
        self.recorder.count(f"access_decisions_{decision.action}")
        self.recorder.count(f"access_reason_{decision.reason}")
        if not decision.allowed or not decision.subject_ref:
            raise _RequestProblem(401, "access_authentication_rejections", "The Bearer grant was rejected", -32003)
        return token, decision.subject_ref

    def _authorize_transport_method(self, method: str, access_token: str | None) -> None:
        if self.access_controller is None:
            return
        if access_token is None:
            raise _RequestProblem(401, "access_authentication_rejections", "A Bearer grant is required", -32003)
        message = {
            "jsonrpc": "2.0",
            "id": f"transport-{method.casefold()}",
            "method": f"transport/{method.casefold()}",
            "params": {},
        }
        decision = self.access_controller.authorize_client_message(access_token, message)
        self.recorder.count(f"access_decisions_{decision.action}")
        self.recorder.count(f"access_reason_{decision.reason}")
        if not decision.allowed:
            raise _RequestProblem(403, "access_authorization_rejections", "Transport operation is not allowed", -32003)

    def _validate_origin(self, request: Request) -> None:
        origins = _raw_header_values(request, "origin")
        if not origins:
            if self.settings.require_origin:
                raise _RequestProblem(403, "origin_rejections", "Origin is required")
            self.recorder.count("origin_absent_allowed")
            return
        if len(origins) != 1:
            raise _RequestProblem(403, "origin_rejections", "Origin is not allowed")
        origin = origins[0]
        self.recorder.add_hash("origin", origin)
        if not _origin_allowed(origin, self.settings.allowed_origins):
            raise _RequestProblem(403, "origin_rejections", "Origin is not allowed")
        self.recorder.count("origin_allowed")

    def _forward_headers(self, request: Request) -> dict[str, str]:
        forwarded: dict[str, str] = {}
        total = 0
        for lower_name, canonical_name in _REQUEST_HEADER_ALLOWLIST.items():
            values = _raw_header_values(request, lower_name)
            if not values:
                continue
            if lower_name == "authorization" and not self.settings.forward_authorization:
                self.recorder.count("authorization_headers_dropped")
                continue
            if lower_name in _SINGLETON_REQUEST_HEADERS and len(values) != 1:
                raise _RequestProblem(400, "duplicate_transport_headers", "A singleton transport header was repeated")
            value = ", ".join(values) if lower_name == "accept" else values[0]
            encoded_size = len(canonical_name.encode("ascii")) + len(value.encode("latin-1"))
            total += encoded_size
            if encoded_size > self.settings.max_transport_header_bytes or total > self.settings.max_transport_header_bytes:
                raise _RequestProblem(431, "oversized_transport_headers", "Transport headers are too large")
            if any(character in value for character in ("\x00", "\r", "\n")):
                raise _RequestProblem(400, "invalid_transport_headers", "A transport header is invalid")
            forwarded[canonical_name] = value
            self.recorder.count(f"headers_forwarded_{lower_name.replace('-', '_')}")
        session_id = forwarded.get("Mcp-Session-Id")
        if session_id:
            self.recorder.add_hash("session", session_id)
        return forwarded

    async def _read_request_body(self, request: Request) -> bytes:
        lengths = _raw_header_values(request, "content-length")
        if len(lengths) > 1:
            raise _RequestProblem(400, "duplicate_content_length", "Content-Length was repeated")
        if lengths:
            try:
                declared = int(lengths[0], 10)
            except ValueError as exc:
                raise _RequestProblem(400, "invalid_content_length", "Content-Length is invalid") from exc
            if declared < 0:
                raise _RequestProblem(400, "invalid_content_length", "Content-Length is invalid")
            if declared > self.settings.max_request_bytes:
                raise _RequestProblem(413, "oversized_requests", "Request body is too large")
        chunks: list[bytes] = []
        size = 0
        try:
            with anyio.fail_after(self.settings.timeout_seconds):
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > self.settings.max_request_bytes:
                        raise _RequestProblem(413, "oversized_requests", "Request body is too large")
                    if chunk:
                        chunks.append(chunk)
        except TimeoutError as exc:
            raise _RequestProblem(408, "request_body_timeouts", "Request body timed out") from exc
        except ClientDisconnect as exc:
            raise _RequestProblem(400, "request_body_disconnects", "Request body was incomplete") from exc
        body = b"".join(chunks)
        if body:
            self.recorder.add_hash("request_body", body)
            self.recorder.count("request_bytes", len(body))
        return body

    async def _handle_post(
        self,
        request: Request,
        headers: dict[str, str],
        body: bytes,
        *,
        access_token: str | None,
        principal_ref: str,
    ) -> Response:
        if _media_type(headers.get("Content-Type", "")) != _JSON:
            raise _RequestProblem(415, "invalid_content_types", "Content-Type must be application/json")
        if not body:
            raise _RequestProblem(400, "malformed_client_json", "POST requires a JSON-RPC body", -32700)
        try:
            value = _parse_json(body)
            messages, is_batch = _validated_messages(value)
        except (_MalformedJSON, _InvalidJSONRPC) as exc:
            raise _RequestProblem(400, "invalid_client_jsonrpc", "Invalid JSON-RPC request", exc.rpc_code) from exc

        expected: dict[str, str] = {}
        client_responses: set[str] = set()
        all_ids: set[str] = set()
        for message in messages:
            kind = _message_kind(message)
            if kind == "notification":
                continue
            key = _rpc_id_key(message.get("id"))
            if key in all_ids:
                raise _LifecycleViolation("duplicate_client_request_ids", "duplicate id in POST")
            all_ids.add(key)
            if kind == "request":
                expected[key] = str(message.get("method"))
            else:
                client_responses.add(key)

        transformed: list[dict[str, Any]] = []
        blocked_rule_ids: set[str] = set()
        blocked = False
        request_transactions: dict[str, str] = {}
        pending_mediations: list[dict[str, Any]] = []
        for message in messages:
            kind = _message_kind(message)
            transaction_id = new_transaction_id()
            if kind != "notification" and "id" in message:
                request_transactions[_rpc_id_key(message.get("id"))] = transaction_id
            if self.access_controller is not None and kind != "response":
                if access_token is None:
                    blocked = True
                    blocked_rule_ids.add("access_token_missing")
                    pending_mediations.append(
                        {
                            "direction": "client_to_upstream",
                            "action": "deny",
                            "message": message,
                            "access_reason": "grant_invalid",
                            "transaction_id": transaction_id,
                            "original_forwarded": False,
                            "safe_replacement_forwarded": False,
                        }
                    )
                    continue
                decision = self.access_controller.authorize_client_message(
                    access_token,
                    message,
                    transaction_ref=transaction_id,
                )
                self.recorder.count(f"access_decisions_{decision.action}")
                self.recorder.count(f"access_reason_{decision.reason}")
                if not decision.allowed:
                    blocked = True
                    blocked_rule_ids.add(f"access:{decision.reason}")
                    pending_mediations.append(
                        {
                            "direction": "client_to_upstream",
                            "action": "deny",
                            "message": message,
                            "access_reason": decision.reason,
                            "transaction_id": transaction_id,
                            "original_forwarded": False,
                            "safe_replacement_forwarded": False,
                        }
                    )
                    continue
            inspected, action, rule_ids, findings = await self.policy.inspect_client(message)
            blocked_rule_ids.update(rule_ids)
            original_forwarded, safe_replacement_forwarded = forwarding_contract(action=action, forwarded=inspected)
            pending_mediations.append(
                {
                    "direction": "client_to_upstream",
                    "action": action,
                    "message": message,
                    "findings": findings,
                    "rule_ids": rule_ids,
                    "transaction_id": transaction_id,
                    "original_forwarded": original_forwarded,
                    "safe_replacement_forwarded": safe_replacement_forwarded,
                }
            )
            if inspected is None:
                blocked = True
            else:
                transformed.append(inspected)
            self.recorder.count(f"client_messages_{action}")
        for mediation in pending_mediations:
            if blocked and mediation["action"] not in {"block", "deny"}:
                mediation["action"] = "block"
                mediation["rule_ids"] = [
                    *list(mediation.get("rule_ids") or []),
                    "BATCH_ATOMIC_BLOCK",
                ]
                mediation["original_forwarded"] = False
                mediation["safe_replacement_forwarded"] = False
            self.recorder.record_mediation(**mediation)
        self.recorder.publish()
        if self.settings.fail_closed_on_report_error and self.recorder.report_write_failed:
            self.recorder.count("report_persistence_rejections")
            return _rpc_error_response(503, -32603, "K-Guard audit persistence is unavailable")
        if blocked:
            self.recorder.count("post_requests_blocked")
            return _blocked_post_response(messages, sorted(blocked_rule_ids), is_batch)

        incoming_session = headers.get("Mcp-Session-Id")
        reservation = await self.lifecycle.reserve_client_responses(
            incoming_session,
            client_responses,
            owner_ref=principal_ref,
        )
        post_lifecycle = _PostLifecycle(expected_responses=expected, transaction_ids=request_transactions)
        outbound_value: Any = transformed if is_batch else transformed[0]
        outbound_body = _dump_json(outbound_value)
        self.recorder.add_hash("forwarded_request_body", outbound_body)
        self.recorder.count("post_requests_forwarded")
        return await self._forward(
            "POST",
            headers,
            outbound_body,
            incoming_session=incoming_session,
            post_lifecycle=post_lifecycle,
            reservation=reservation,
            access_token=access_token,
            principal_ref=principal_ref,
        )

    async def _forward(
        self,
        method: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        incoming_session: str | None,
        post_lifecycle: _PostLifecycle | None,
        reservation: _Reservation | None,
        access_token: str | None,
        principal_ref: str,
    ) -> Response:
        upstream: httpx.Response | None = None
        response_headers: dict[str, str] = {}
        reservation_settled = False
        try:
            request = httpx.Request(
                method,
                self.upstream_url,
                headers=headers,
                content=body,
                extensions={"timeout": httpx.Timeout(self.settings.timeout_seconds).as_dict()},
            )
            try:
                with anyio.fail_after(self.settings.timeout_seconds):
                    upstream = await self.client.send(
                        request,
                        stream=True,
                        auth=None,
                        follow_redirects=False,
                    )
            except (TimeoutError, httpx.TimeoutException) as exc:
                raise _UpstreamFailure(504, "upstream_timeouts", "Upstream request timed out") from exc
            except httpx.HTTPError as exc:
                raise _UpstreamFailure(502, "upstream_connection_errors", "Upstream request failed") from exc

            self.recorder.count(f"upstream_status_{upstream.status_code}")
            self.recorder.add_hash("upstream_status", str(upstream.status_code))
            if 300 <= upstream.status_code < 400:
                location = upstream.headers.get("location")
                if location:
                    self.recorder.add_hash("blocked_redirect_location", location)
                raise _UpstreamFailure(502, "upstream_redirects_blocked", "Upstream redirects are not followed")

            response_headers, upstream_session = _safe_response_headers(upstream)
            if upstream_session:
                self.recorder.add_hash("session", upstream_session)
            if incoming_session and upstream_session and incoming_session != upstream_session:
                raise _UpstreamFailure(502, "upstream_session_mismatches", "Upstream session changed unexpectedly")
            stream_session = upstream_session or incoming_session
            successful = 200 <= upstream.status_code < 300
            if reservation is not None:
                if successful:
                    await reservation.commit()
                else:
                    await reservation.release()
                reservation_settled = True

            content_type = _media_type(upstream.headers.get("content-type", ""))
            if content_type == _SSE:
                if method not in {"POST", "GET"}:
                    raise _UpstreamFailure(502, "unexpected_sse_responses", "DELETE cannot return an SSE stream")
                if not await self._reserve_sse_stream():
                    raise _UpstreamFailure(503, "sse_concurrency_limit_exceeded", "SSE stream capacity is exhausted")
                status_code = upstream.status_code
                body_iterator = self._stream_sse(
                    upstream,
                    post_lifecycle if successful else None,
                    stream_session,
                    access_token,
                    principal_ref,
                )
                upstream = None
                self.recorder.count("sse_streams_forwarded")
                return StreamingResponse(
                    body_iterator,
                    status_code=status_code,
                    headers=response_headers,
                    media_type=None,
                )

            status_code = upstream.status_code
            response_body = await self._read_bounded_response(upstream)
            await upstream.aclose()
            upstream = None
            if not response_body:
                if successful and post_lifecycle is not None and post_lifecycle.missing_response_ids:
                    raise _UpstreamFailure(502, "missing_upstream_responses", "Upstream omitted a JSON-RPC response")
                response = Response(content=b"", status_code=status_code, headers=response_headers)
                if method == "DELETE" and successful and incoming_session:
                    await self._clear_session(incoming_session, owner_ref=principal_ref)
                return response
            if content_type != _JSON:
                raise _UpstreamFailure(502, "unsupported_upstream_content_types", "Upstream response type is unsupported")
            try:
                value = _parse_json(response_body)
                _validated_messages(value)
            except (_MalformedJSON, _InvalidJSONRPC) as exc:
                raise _UpstreamFailure(502, "malformed_upstream_json", "Upstream returned invalid JSON-RPC") from exc
            transformed = await self._inspect_upstream_value(
                value,
                post_lifecycle if successful else None,
                stream_session,
                access_token,
                principal_ref,
            )
            if transformed is None:
                raise _UpstreamFailure(502, "fully_blocked_upstream_payloads", "Upstream payload was blocked")
            if successful and post_lifecycle is not None and post_lifecycle.missing_response_ids:
                raise _UpstreamFailure(502, "missing_upstream_responses", "Upstream omitted a JSON-RPC response")
            serialized = _dump_json(transformed)
            self.recorder.add_hash("forwarded_response_body", serialized)
            self.recorder.count("json_responses_forwarded")
            response = Response(content=serialized, status_code=status_code, headers=response_headers)
            if method == "DELETE" and successful and incoming_session:
                await self._clear_session(incoming_session, owner_ref=principal_ref)
            return response
        except _PolicyControlFailure as exc:
            self.recorder.control_error(exc.kind, exc)
            return _rpc_error_response(500, -32603, "K-Guard policy control failed closed", headers=response_headers)
        except _LifecycleViolation as exc:
            self.recorder.control_error(exc.kind, exc)
            return _rpc_error_response(502, -32002, "K-Guard blocked an invalid upstream lifecycle", headers=response_headers)
        except _UpstreamFailure as exc:
            self.recorder.control_error(exc.kind, exc)
            return _rpc_error_response(exc.status_code, -32002, exc.safe_message, headers=response_headers)
        except Exception as exc:
            self.recorder.control_error("unexpected_upstream_control_error", exc)
            return _rpc_error_response(502, -32002, "K-Guard failed closed on an upstream control error", headers=response_headers)
        finally:
            if upstream is not None:
                await upstream.aclose()
            if reservation is not None and not reservation_settled:
                await reservation.release()

    async def _read_bounded_response(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length")
        if declared:
            try:
                declared_size = int(declared, 10)
                if declared_size < 0:
                    raise ValueError("negative content length")
                if declared_size > self.settings.max_response_bytes:
                    raise _UpstreamFailure(502, "oversized_upstream_responses", "Upstream response is too large")
            except ValueError as exc:
                raise _UpstreamFailure(502, "invalid_upstream_content_lengths", "Upstream Content-Length is invalid") from exc
        chunks: list[bytes] = []
        size = 0
        iterator = response.aiter_bytes().__aiter__()
        while True:
            try:
                with anyio.fail_after(self.settings.timeout_seconds):
                    chunk = await iterator.__anext__()
            except StopAsyncIteration:
                break
            except (TimeoutError, httpx.TimeoutException) as exc:
                raise _UpstreamFailure(504, "upstream_timeouts", "Upstream response timed out") from exc
            size += len(chunk)
            if size > self.settings.max_response_bytes:
                raise _UpstreamFailure(502, "oversized_upstream_responses", "Upstream response is too large")
            if chunk:
                chunks.append(chunk)
        self.recorder.count("upstream_response_bytes", size)
        return b"".join(chunks)

    async def _inspect_upstream_value(
        self,
        value: Any,
        post_lifecycle: _PostLifecycle | None,
        session_id: str | None,
        access_token: str | None = None,
        principal_ref: str = "anonymous",
    ) -> Any | None:
        messages, is_batch = _validated_messages(value)
        forwarded: list[dict[str, Any]] = []
        server_request_keys: list[str] = []
        for message in messages:
            kind = _message_kind(message)
            related_method = None
            if kind == "response" and post_lifecycle is not None:
                related_method = post_lifecycle.accept_response(_rpc_id_key(message.get("id")))
            inspected = await self.policy.inspect_upstream(
                message,
                is_response=kind == "response",
                related_method=related_method,
            )
            if len(inspected) == 2:
                transformed, action = inspected
                findings = []
            else:
                transformed, action, findings = inspected
            if (
                transformed is not None
                and self.access_controller is not None
                and access_token is not None
                and related_method == "tools/list"
            ):
                filtered = self.access_controller.filter_tools_list_response(access_token, transformed)
                if filtered != transformed:
                    action = "redact"
                    self.recorder.count("access_tool_lists_filtered")
                transformed = filtered
            transaction_id = ""
            if kind != "notification" and "id" in message:
                key = _rpc_id_key(message.get("id"))
                if post_lifecycle is not None:
                    transaction_id = post_lifecycle.transaction_ids.get(key, "")
                    if kind == "request":
                        post_lifecycle.transaction_ids[key] = transaction_id or new_transaction_id()
                        transaction_id = post_lifecycle.transaction_ids[key]
            transaction_id = transaction_id or new_transaction_id()
            original_forwarded, safe_replacement_forwarded = forwarding_contract(action=action, forwarded=transformed)
            self.recorder.record_mediation(
                direction="upstream_to_client",
                action=action,
                message=message,
                findings=findings,
                transaction_id=transaction_id,
                original_forwarded=original_forwarded,
                safe_replacement_forwarded=safe_replacement_forwarded,
            )
            self.recorder.count(f"upstream_messages_{action}")
            if transformed is None:
                continue
            if kind == "request":
                key = _rpc_id_key(transformed.get("id"))
                if post_lifecycle is not None:
                    post_lifecycle.accept_server_request(key)
                server_request_keys.append(key)
            forwarded.append(transformed)
        if server_request_keys:
            await self.lifecycle.register_server_requests(
                session_id,
                server_request_keys,
                owner_ref=principal_ref,
            )
            self.recorder.count("server_requests_correlated", len(server_request_keys))
        if not forwarded:
            return None
        return forwarded if is_batch else forwarded[0]

    async def _stream_sse(
        self,
        response: httpx.Response,
        post_lifecycle: _PostLifecycle | None,
        session_id: str | None,
        access_token: str | None = None,
        principal_ref: str = "anonymous",
    ) -> AsyncIterator[bytes]:
        parser = _IncrementalSSEParser(self.settings.max_sse_event_bytes)
        failed = False
        normal_end = False
        stream_bytes = 0
        event_count = 0
        started = time.monotonic()
        iterator = response.aiter_bytes().__aiter__()
        try:
            while True:
                if time.monotonic() - started > self.settings.max_sse_stream_seconds:
                    raise _SSEFailure("sse_stream_duration_limit_exceeded", "SSE stream duration limit exceeded")
                try:
                    with anyio.fail_after(self.settings.timeout_seconds):
                        chunk = await iterator.__anext__()
                except StopAsyncIteration:
                    break
                except (TimeoutError, httpx.TimeoutException) as exc:
                    raise _SSEFailure("sse_upstream_timeouts", "SSE stream timed out") from exc
                stream_bytes += len(chunk)
                if stream_bytes > self.settings.max_sse_stream_bytes:
                    raise _SSEFailure("sse_stream_byte_limit_exceeded", "SSE stream byte limit exceeded")
                for event in parser.feed(chunk):
                    event_count += 1
                    if event_count > self.settings.max_sse_events:
                        raise _SSEFailure("sse_event_count_limit_exceeded", "SSE event count limit exceeded")
                    transformed = await self._transform_sse_event(
                        event,
                        post_lifecycle,
                        session_id,
                        access_token,
                        principal_ref,
                    )
                    if transformed is not None:
                        self.recorder.count("sse_events_forwarded")
                        yield transformed
                    else:
                        self.recorder.count("sse_events_blocked")
            parser.finish()
            if post_lifecycle is not None and post_lifecycle.missing_response_ids:
                raise _SSEFailure("missing_upstream_responses", "SSE ended before every response arrived")
            normal_end = True
        except _PolicyControlFailure as exc:
            failed = True
            self.recorder.control_error(exc.kind, exc)
            yield _sse_fail_closed_event()
        except (_MalformedSSE, _InvalidJSONRPC, _LifecycleViolation, _SSEFailure) as exc:
            failed = True
            self.recorder.control_error(getattr(exc, "kind", "malformed_sse_events"), exc)
            yield _sse_fail_closed_event()
        except httpx.HTTPError as exc:
            failed = True
            self.recorder.control_error("sse_upstream_errors", exc)
            yield _sse_fail_closed_event()
        except Exception as exc:
            failed = True
            self.recorder.control_error("unexpected_sse_control_error", exc)
            yield _sse_fail_closed_event()
        finally:
            await response.aclose()
            await self._release_sse_stream()
            if post_lifecycle is not None and post_lifecycle.missing_response_ids and not failed and not normal_end:
                self.recorder.control_error(
                    "incomplete_downstream_sse_delivery",
                    RuntimeError("downstream stream ended before correlated responses completed"),
                )
            self.recorder.publish()

    async def _transform_sse_event(
        self,
        event: _SSEEvent,
        post_lifecycle: _PostLifecycle | None,
        session_id: str | None,
        access_token: str | None = None,
        principal_ref: str = "anonymous",
    ) -> bytes | None:
        metadata_action = await self.policy.inspect_sse_metadata(event.metadata_text())
        if metadata_action == "block":
            return None
        data = event.data
        if data is None or data == "":
            self.recorder.count("sse_control_events_forwarded")
            return event.raw
        try:
            value = _parse_json(data.encode("utf-8"))
            _validated_messages(value)
        except (_MalformedJSON, _InvalidJSONRPC) as exc:
            raise _MalformedSSE("malformed_sse_json", "SSE data is not valid JSON-RPC") from exc
        transformed = await self._inspect_upstream_value(
            value,
            post_lifecycle,
            session_id,
            access_token,
            principal_ref,
        )
        if transformed is None:
            return None
        self.recorder.add_hash("sse_data", data)
        if transformed == value:
            return event.raw
        return event.replace_data(_dump_json(transformed).decode("utf-8"))

    async def _clear_session(self, session_id: str, *, owner_ref: str = "anonymous") -> None:
        pending = await self.lifecycle.clear_session(session_id, owner_ref=owner_ref)
        self.recorder.count("sessions_deleted")
        if pending:
            self.recorder.count("pending_server_requests_cancelled", pending)

    async def _reserve_sse_stream(self) -> bool:
        async with self._sse_lock:
            if self._active_sse_streams >= self.settings.max_concurrent_sse_streams:
                return False
            self._active_sse_streams += 1
            self.recorder.count("sse_stream_reservations")
            return True

    async def _release_sse_stream(self) -> None:
        async with self._sse_lock:
            self._active_sse_streams = max(0, self._active_sse_streams - 1)

    async def finalize(self) -> None:
        pending = await self.lifecycle.pending_count()
        if pending:
            self.recorder.control_error(
                "unanswered_server_requests",
                RuntimeError(f"pending_server_request_count={pending}"),
            )


class _RuntimePolicy:
    def __init__(self, recorder: _ReportRecorder) -> None:
        self.observer = McpRuntimeObserver()
        self.recorder = recorder
        self.lock = asyncio.Lock()

    async def inspect_client(
        self,
        message: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str, list[str], list[Any]]:
        policy_message, protocol_version = _shield_protocol_version(message, method=str(message.get("method") or ""))
        try:
            async with self.lock:
                findings, transformed, action, rule_ids = _stdio_proxy._enforce_client_message(
                    self.observer,
                    policy_message,
                )
        except Exception as exc:
            raise _PolicyControlFailure("client_policy_control_errors", "client policy failed") from exc
        self.recorder.add_findings(findings)
        if action not in {"allow", "redact", "block"}:
            raise _PolicyControlFailure("invalid_client_policy_actions", "client policy returned an invalid action")
        if transformed is not None:
            transformed = _restore_protocol_version(transformed, "params", protocol_version)
            _validate_policy_transform(message, transformed)
            self.recorder.add_hash("client_policy_output", transformed)
        return transformed, action, [str(item) for item in rule_ids], findings

    async def inspect_upstream(
        self,
        message: dict[str, Any],
        *,
        is_response: bool,
        related_method: str | None,
    ) -> tuple[dict[str, Any] | None, str, list[Any]]:
        policy_message, protocol_version = _shield_protocol_version(message, method=related_method or "")
        try:
            async with self.lock:
                result, transformed, action = _stdio_proxy._enforce_upstream_message(
                    self.observer,
                    policy_message,
                    is_response=is_response,
                )
        except Exception as exc:
            raise _PolicyControlFailure("upstream_policy_control_errors", "upstream policy failed") from exc
        self.recorder.add_findings(result.findings)
        if action not in {"allow", "redact", "block"}:
            raise _PolicyControlFailure("invalid_upstream_policy_actions", "upstream policy returned an invalid action")
        if transformed is not None:
            transformed = _restore_protocol_version(transformed, "result", protocol_version)
            _validate_policy_transform(message, transformed)
            self.recorder.add_hash("upstream_policy_output", transformed)
        return transformed, action, list(result.findings)

    async def inspect_sse_metadata(self, metadata: str) -> str:
        if not metadata:
            return "allow"
        try:
            async with self.lock:
                secret_findings = self.observer.secret_detector.scan_text(metadata, "mcp-http-proxy:sse-metadata")
                threat_findings = self.observer.mcp_threat_detector.scan_text(metadata, "mcp-http-proxy:sse-metadata")
                pii_findings, _entities = self.observer.pii_detector.scan_text(metadata, "mcp-http-proxy:sse-metadata")
        except Exception as exc:
            raise _PolicyControlFailure("sse_metadata_policy_control_errors", "SSE metadata policy failed") from exc
        findings = [*secret_findings, *threat_findings, *pii_findings]
        self.recorder.add_findings(findings)
        if findings:
            self.recorder.count("sse_metadata_blocks")
            return "block"
        self.recorder.add_hash("sse_metadata", metadata)
        return "allow"


@dataclass(slots=True)
class _PostLifecycle:
    expected_responses: dict[str, str]
    transaction_ids: dict[str, str] = field(default_factory=dict)
    seen_response_ids: set[str] = field(default_factory=set)
    seen_server_request_ids: set[str] = field(default_factory=set)

    def accept_response(self, key: str) -> str:
        if key not in self.expected_responses:
            raise _LifecycleViolation("uncorrelated_upstream_responses", "response id was not requested in this POST")
        if key in self.seen_response_ids:
            raise _LifecycleViolation("duplicate_upstream_responses", "response id was repeated in this POST")
        self.seen_response_ids.add(key)
        return self.expected_responses[key]

    def accept_server_request(self, key: str) -> None:
        if key in self.seen_server_request_ids:
            raise _LifecycleViolation("duplicate_upstream_request_ids", "server request id was repeated in this POST")
        self.seen_server_request_ids.add(key)

    @property
    def missing_response_ids(self) -> set[str]:
        return set(self.expected_responses) - self.seen_response_ids


class _LifecycleRegistry:
    def __init__(self, max_sessions: int, max_pending_per_session: int) -> None:
        self.max_sessions = max_sessions
        self.max_pending_per_session = max_pending_per_session
        self.pending: dict[tuple[str, str], dict[str, str | None]] = {}
        self.lock = asyncio.Lock()

    async def register_server_requests(
        self,
        session_id: str | None,
        keys: Iterable[str],
        *,
        owner_ref: str = "anonymous",
    ) -> None:
        supplied = list(keys)
        unique = list(dict.fromkeys(supplied))
        if len(unique) != len(supplied):
            raise _LifecycleViolation("duplicate_upstream_request_ids", "server request id was repeated")
        if not unique:
            return
        if not session_id:
            raise _LifecycleViolation("uncorrelatable_server_requests", "server request has no MCP session")
        session_key = (owner_ref, session_id)
        async with self.lock:
            if session_key not in self.pending and len(self.pending) >= self.max_sessions:
                raise _LifecycleViolation("lifecycle_session_capacity_exceeded", "lifecycle session capacity was exceeded")
            session = self.pending.setdefault(session_key, {})
            if any(key in session for key in unique):
                raise _LifecycleViolation("duplicate_upstream_request_ids", "server request id is already outstanding")
            if len(session) + len(unique) > self.max_pending_per_session:
                raise _LifecycleViolation("lifecycle_request_capacity_exceeded", "pending request capacity was exceeded")
            for key in unique:
                session[key] = None

    async def reserve_client_responses(
        self,
        session_id: str | None,
        keys: set[str],
        *,
        owner_ref: str = "anonymous",
    ) -> _Reservation | None:
        if not keys:
            return None
        if not session_id:
            raise _LifecycleViolation("uncorrelated_client_responses", "client response has no MCP session")
        session_key = (owner_ref, session_id)
        token = secrets.token_hex(16)
        async with self.lock:
            session = self.pending.get(session_key)
            if session is None or any(key not in session or session[key] is not None for key in keys):
                raise _LifecycleViolation("uncorrelated_client_responses", "client response has no pending server request")
            for key in keys:
                session[key] = token
        return _Reservation(self, session_key, frozenset(keys), token)

    async def settle(self, reservation: _Reservation, *, commit: bool) -> None:
        async with self.lock:
            session = self.pending.get(reservation.session_key)
            if session is None:
                return
            for key in reservation.keys:
                if session.get(key) != reservation.token:
                    continue
                if commit:
                    session.pop(key, None)
                else:
                    session[key] = None
            if not session:
                self.pending.pop(reservation.session_key, None)

    async def clear_session(self, session_id: str, *, owner_ref: str = "anonymous") -> int:
        async with self.lock:
            return len(self.pending.pop((owner_ref, session_id), {}))

    async def pending_count(self) -> int:
        async with self.lock:
            return sum(len(session) for session in self.pending.values())


@dataclass(slots=True)
class _Reservation:
    registry: _LifecycleRegistry
    session_key: tuple[str, str]
    keys: frozenset[str]
    token: str
    settled: bool = False

    async def commit(self) -> None:
        if not self.settled:
            await self.registry.settle(self, commit=True)
            self.settled = True

    async def release(self) -> None:
        if not self.settled:
            await self.registry.settle(self, commit=False)
            self.settled = True


@dataclass(frozen=True, slots=True)
class _SSEEvent:
    raw: bytes
    lines: tuple[str, ...]
    data: str | None

    def metadata_text(self) -> str:
        values: list[str] = []
        for line in self.lines:
            if line.startswith("data:") or line == "data":
                continue
            name, separator, value = line.partition(":")
            if name in {"id", "retry", "event"}:
                continue
            if line.startswith(":"):
                values.append(line[1:])
            elif separator:
                values.append(value.lstrip())
            else:
                values.append(line)
        return "\n".join(item for item in values if item)

    def replace_data(self, data: str) -> bytes:
        output: list[str] = []
        inserted = False
        for line in self.lines:
            name = line.split(":", 1)[0]
            if name == "data":
                if not inserted:
                    output.append(f"data: {data}")
                    inserted = True
                continue
            output.append(line)
        if not inserted:
            output.append(f"data: {data}")
        return ("\n".join(output) + "\n\n").encode("utf-8")


class _IncrementalSSEParser:
    def __init__(self, max_event_bytes: int) -> None:
        self.max_event_bytes = max_event_bytes
        self.pending_line = bytearray()
        self.event_lines: list[bytes] = []
        self.event_raw = bytearray()
        self.at_stream_start = True

    def feed(self, chunk: bytes) -> Iterator[_SSEEvent]:
        segment_size = min(self.max_event_bytes, 64 * 1024)
        view = memoryview(chunk)
        for offset in range(0, len(view), segment_size):
            self.pending_line.extend(view[offset : offset + segment_size])
            while True:
                ending = self._line_ending()
                if ending is None:
                    if len(self.event_raw) + len(self.pending_line) > self.max_event_bytes:
                        raise _MalformedSSE("oversized_sse_events", "SSE event exceeded its byte limit")
                    break
                index, width = ending
                line = bytes(self.pending_line[:index])
                terminator = bytes(self.pending_line[index : index + width])
                del self.pending_line[: index + width]
                if self.at_stream_start:
                    self.at_stream_start = False
                    if line.startswith(b"\xef\xbb\xbf"):
                        line = line[3:]
                self.event_raw.extend(line)
                self.event_raw.extend(terminator)
                if len(self.event_raw) > self.max_event_bytes:
                    raise _MalformedSSE("oversized_sse_events", "SSE event exceeded its byte limit")
                if line:
                    self.event_lines.append(line)
                    continue
                if self.event_lines:
                    yield self._build_event()
                self.event_lines = []
                self.event_raw = bytearray()

    def finish(self) -> None:
        if self.pending_line or self.event_lines or self.event_raw:
            raise _MalformedSSE("incomplete_sse_events", "SSE stream ended in a partial event")

    def _line_ending(self) -> tuple[int, int] | None:
        for index, value in enumerate(self.pending_line):
            if value == 10:
                return index, 1
            if value == 13:
                if index + 1 == len(self.pending_line):
                    return None
                return index, 2 if self.pending_line[index + 1] == 10 else 1
        return None

    def _build_event(self) -> _SSEEvent:
        try:
            lines = tuple(line.decode("utf-8", errors="strict") for line in self.event_lines)
        except UnicodeDecodeError as exc:
            raise _MalformedSSE("malformed_sse_utf8", "SSE event is not valid UTF-8") from exc
        data_values: list[str] = []
        for line in lines:
            if line.startswith(":"):
                continue
            name, separator, value = line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if name == "data":
                data_values.append(value)
        data = "\n".join(data_values) if data_values else None
        return _SSEEvent(bytes(self.event_raw), lines, data)


class _ReportRecorder:
    def __init__(
        self,
        upstream_url: str,
        settings: McpHttpProxySettings,
        *,
        access_controller: AccessPolicyController | None = None,
    ) -> None:
        self.upstream_ref = evidence_hash(upstream_url)
        self.endpoint_ref = evidence_hash(settings.endpoint_path)
        self.allowed_origin_refs = [evidence_hash(item) for item in settings.allowed_origins]
        self.run_ref = evidence_hash(secrets.token_hex(32))
        self.started_at = datetime.now(UTC).isoformat()
        self.toolchain_contract = mcp_http_proxy_toolchain_contract()
        self.report_path = Path(settings.report_path) if settings.report_path is not None else None
        persist_path = (
            Path(settings.receipt_log_path)
            if settings.receipt_log_path is not None
            else receipt_persist_path_for_report(settings.report_path)
        )
        self.receipt_chain = RuntimeMediationReceiptChain(
            transport="streamable_http",
            toolchain_ref=str(self.toolchain_contract.get("sha256") or ("0" * 64)),
            policy_ref=policy_ref_for(
                access_controller.policy.source_sha256 if access_controller is not None else None
            ),
            persist_path=persist_path,
        )
        self.access_controller = access_controller
        self.settings_contract = {
            "max_request_bytes": settings.max_request_bytes,
            "max_response_bytes": settings.max_response_bytes,
            "max_sse_event_bytes": settings.max_sse_event_bytes,
            "max_sse_stream_bytes": settings.max_sse_stream_bytes,
            "max_sse_events": settings.max_sse_events,
            "max_sse_stream_seconds": settings.max_sse_stream_seconds,
            "max_concurrent_sse_streams": settings.max_concurrent_sse_streams,
            "max_transport_header_bytes": settings.max_transport_header_bytes,
            "timeout_seconds": settings.timeout_seconds,
            "forward_authorization": settings.forward_authorization,
            "require_origin": settings.require_origin,
            "fail_closed_on_report_error": settings.fail_closed_on_report_error,
            "max_lifecycle_sessions": settings.max_lifecycle_sessions,
            "max_pending_server_requests_per_session": settings.max_pending_server_requests_per_session,
            "receipt_log_configured": persist_path is not None,
        }
        self.stats: Counter[str] = Counter()
        self.findings: list[dict[str, Any]] = []
        self.control_errors: list[dict[str, str]] = []
        self.hashes: dict[str, tuple[int, str]] = {}
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.app: Starlette | None = None
        self.report_write_failed = False
        self.snapshot_cache_key = ""
        self.snapshot_cache: dict[str, Any] | None = None

    def attach_app(self, app: Starlette) -> None:
        self.app = app
        app.state.k_guard_proxy_reporter = self
        app.state.k_guard_report = self.snapshot()

    def count(self, key: str, amount: int = 1) -> None:
        with self.lock:
            self.stats[key] += int(amount)

    def add_hash(self, category: str, value: Any) -> None:
        if isinstance(value, bytes):
            serialized = value.hex()
        elif isinstance(value, str):
            serialized = value
        else:
            serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        item_ref = evidence_hash(serialized)
        with self.lock:
            count, chain = self.hashes.get(category, (0, evidence_hash(f"k-guard:{category}")))
            self.hashes[category] = (count + 1, evidence_hash(f"{chain}:{item_ref}"))

    def add_findings(self, findings: Iterable[Any]) -> None:
        converted: list[dict[str, Any]] = []
        for finding in findings:
            if hasattr(finding, "to_dict"):
                item = finding.to_dict()
            elif isinstance(finding, dict):
                item = dict(finding)
            else:
                item = {"finding_ref": evidence_hash(str(finding)), "raw_returned": False}
            converted.append(item)
        if not converted:
            return
        with self.lock:
            self.findings.extend(converted)
            self.stats["findings_total"] += len(converted)

    def control_error(self, kind: str, exc: BaseException) -> None:
        entry = {
            "kind": kind,
            "type": type(exc).__name__,
            "detail_ref": evidence_hash(f"{type(exc).__name__}:{exc}"),
        }
        with self.lock:
            self.control_errors.append(entry)
            self.stats["control_errors_total"] += 1
            self.stats[f"control_error_{kind}"] += 1

    def record_mediation(self, **kwargs: Any) -> dict[str, Any]:
        try:
            receipt = self.receipt_chain.record(**kwargs)
        except RuntimeMediationReceiptError as exc:
            self.control_error("mediation_receipt_persist_failed", exc)
            self.report_write_failed = True
            raise _PolicyControlFailure("mediation_receipt_persist_failed", "K-Guard could not persist a mediation receipt") from exc
        with self.lock:
            self.snapshot_cache_key = ""
            self.snapshot_cache = None
        return receipt

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            complete = not self.control_errors
            counts = dict(sorted(self.stats.items()))
            control_errors = list(self.control_errors)
            runtime_exercised = (
                int(counts.get("post_requests_forwarded", 0)) > 0
                and int(counts.get("json_responses_forwarded", 0))
                + int(counts.get("sse_streams_forwarded", 0))
                > 0
            )
            passed = complete and runtime_exercised
            report = {
                "schema": "k_guard_mcp_http_proxy_report.v1",
                "raw_free": True,
                "transport": "streamable_http",
                "mode": "live_reverse_proxy",
                "run_ref": self.run_ref,
                "complete": complete,
                "passed": passed,
                "coverage_gap": not passed,
                "control_status": "completed" if passed else ("not_exercised" if complete else "failed_closed"),
                "execution": {
                    "started_at": self.started_at,
                    "runtime_exercised": runtime_exercised,
                    "toolchain_sha256": self.toolchain_contract.get("sha256", ""),
                    "toolchain_contract": self.toolchain_contract,
                    "raw_returned": False,
                },
                "upstream": {
                    "url_ref": self.upstream_ref,
                    "fixed": True,
                    "redirects_followed": False,
                },
                "policy": {
                    "endpoint_ref": self.endpoint_ref,
                    "allowed_origin_count": len(self.allowed_origin_refs),
                    "allowed_origin_refs": list(self.allowed_origin_refs),
                    "hash_scheme": evidence_hash_scheme(),
                    "settings": dict(self.settings_contract),
                    "audit_persistence": {
                        "configured": self.report_path is not None,
                        "healthy": not self.report_write_failed,
                        "fail_closed_on_error": self.settings_contract["fail_closed_on_report_error"],
                    },
                },
                "enforcement_contract": {
                    "client_to_server": "inspect_block_or_redact_before_forward",
                    "server_to_client": "inspect_block_or_redact_before_forward",
                    "sse_complete_event_buffering": True,
                    "request_response_correlation": True,
                    "fail_closed_on_control_gap": True,
                    "receipt_persist_before_forward": True,
                    "raw_returned": False,
                },
                "access_control": (
                    self.access_controller.summary()
                    if self.access_controller is not None
                    else {
                        "enabled": False,
                        "default_action": "content-policy-only",
                        "raw_free": True,
                        "raw_returned": False,
                    }
                ),
                "counts": counts,
                "stats": counts,
                "hashes": {
                    key: {"count": count, "chain_hash": chain}
                    for key, (count, chain) in sorted(self.hashes.items())
                },
                "finding_count": len(self.findings),
                "findings": list(self.findings),
                "control_errors": control_errors,
                "errors": control_errors,
            }
        sanitized = sanitize_any(report)
        sanitized["mediation_receipts"] = self.receipt_chain.export()
        state_key = hashlib.sha256(
            json.dumps(sanitized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self.lock:
            if state_key == self.snapshot_cache_key and self.snapshot_cache is not None:
                return json.loads(json.dumps(self.snapshot_cache, ensure_ascii=False))
        sanitized["execution"]["observed_at"] = datetime.now(UTC).isoformat()
        sanitized["evidence_bundle"] = evidence_bundle(
            subject="mcp_streamable_http_runtime",
            producer="k_guard_mcp.mcp_http_proxy",
            artifacts=[object_artifact("runtime-report", sanitized, role="runtime")],
        )
        with self.lock:
            self.snapshot_cache_key = state_key
            self.snapshot_cache = json.loads(json.dumps(sanitized, ensure_ascii=False))
            return json.loads(json.dumps(self.snapshot_cache, ensure_ascii=False))

    def publish(self) -> None:
        report = self.snapshot()
        if self.app is not None:
            self.app.state.k_guard_report = report
        if self.report_path is None or self.report_write_failed:
            return
        try:
            with self.write_lock:
                self.report_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.report_path.with_name(self.report_path.name + ".tmp")
                temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                temporary.replace(self.report_path)
        except OSError as exc:
            self.report_write_failed = True
            self.control_error("report_write_errors", exc)
            if self.app is not None:
                self.app.state.k_guard_report = self.snapshot()


class _RequestProblem(Exception):
    def __init__(self, status_code: int, kind: str, safe_message: str, rpc_code: int = -32600) -> None:
        super().__init__(safe_message)
        self.status_code = status_code
        self.kind = kind
        self.safe_message = safe_message
        self.rpc_code = rpc_code


class _UpstreamFailure(Exception):
    def __init__(self, status_code: int, kind: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.status_code = status_code
        self.kind = kind
        self.safe_message = safe_message


class _PolicyControlFailure(Exception):
    def __init__(self, kind: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.kind = kind


class _LifecycleViolation(Exception):
    def __init__(self, kind: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.kind = kind


class _MalformedJSON(Exception):
    rpc_code = -32700


class _InvalidJSONRPC(Exception):
    rpc_code = -32600


class _MalformedSSE(Exception):
    def __init__(self, kind: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.kind = kind


class _SSEFailure(Exception):
    def __init__(self, kind: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.kind = kind


def _validated_messages(value: Any) -> tuple[list[dict[str, Any]], bool]:
    is_batch = isinstance(value, list)
    if is_batch:
        if not value:
            raise _InvalidJSONRPC("JSON-RPC batch must not be empty")
        candidates = value
    else:
        candidates = [value]
    if any(not isinstance(item, dict) for item in candidates):
        raise _InvalidJSONRPC("JSON-RPC messages must be objects")
    messages = [dict(item) for item in candidates]
    for message in messages:
        _message_kind(message)
    return messages, is_batch


def _message_kind(message: dict[str, Any]) -> str:
    if _stdio_proxy._is_valid_jsonrpc_response(message) and _strict_rpc_id(message.get("id")):
        return "response"
    if _stdio_proxy._is_valid_jsonrpc_request(message):
        if "id" in message and not _strict_rpc_id(message.get("id")):
            raise _InvalidJSONRPC("JSON-RPC id is invalid")
        return "request" if "id" in message else "notification"
    raise _InvalidJSONRPC("JSON-RPC envelope is invalid")


def _strict_rpc_id(value: Any) -> bool:
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return not isinstance(value, float) or math.isfinite(value)


def _shield_protocol_version(
    message: dict[str, Any],
    *,
    method: str,
) -> tuple[dict[str, Any], str | None]:
    if method != "initialize":
        return message, None
    payload_key = "params" if "method" in message else "result"
    payload = message.get(payload_key)
    if not isinstance(payload, dict):
        return message, None
    protocol_version = payload.get("protocolVersion")
    if not isinstance(protocol_version, str) or not _is_protocol_date(protocol_version):
        return message, None
    shielded_payload = dict(payload)
    shielded_payload["protocolVersion"] = _PROTOCOL_VERSION_PLACEHOLDER
    shielded = dict(message)
    shielded[payload_key] = shielded_payload
    return shielded, protocol_version


def _restore_protocol_version(
    message: dict[str, Any],
    payload_key: str,
    protocol_version: str | None,
) -> dict[str, Any]:
    if protocol_version is None:
        return message
    payload = message.get(payload_key)
    if not isinstance(payload, dict) or payload.get("protocolVersion") != _PROTOCOL_VERSION_PLACEHOLDER:
        return message
    restored_payload = dict(payload)
    restored_payload["protocolVersion"] = protocol_version
    restored = dict(message)
    restored[payload_key] = restored_payload
    return restored


def _is_protocol_date(value: str) -> bool:
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _validate_policy_transform(original: dict[str, Any], transformed: dict[str, Any]) -> None:
    if not isinstance(transformed, dict):
        raise _PolicyControlFailure("invalid_policy_transforms", "policy transform was not an object")
    original_kind = _message_kind(original)
    transformed_kind = _message_kind(transformed)
    if original_kind != transformed_kind:
        raise _PolicyControlFailure("invalid_policy_transforms", "policy transform changed message kind")
    if "id" in original and _rpc_id_key(original.get("id")) != _rpc_id_key(transformed.get("id")):
        raise _PolicyControlFailure("invalid_policy_transforms", "policy transform changed message id")
    if "method" in original and original.get("method") != transformed.get("method"):
        raise _PolicyControlFailure("invalid_policy_transforms", "policy transform changed method")


def _parse_json(body: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise _MalformedJSON("non-finite JSON number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _MalformedJSON("duplicate JSON object key")
            result[key] = value
        return result

    try:
        return json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _MalformedJSON("malformed JSON") from exc


def _dump_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _rpc_id_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _blocked_post_response(
    messages: list[dict[str, Any]],
    rule_ids: list[str],
    was_batch: bool,
) -> JSONResponse:
    payloads = [
        _stdio_proxy._blocked_client_response(message.get("id"), rule_ids)
        for message in messages
        if _message_kind(message) == "request"
    ]
    if not payloads:
        payloads = [_stdio_proxy._blocked_client_response(None, rule_ids)]
    payload: Any = payloads if was_batch else payloads[0]
    return JSONResponse(payload, status_code=403)


def _rpc_error_response(
    status_code: int,
    code: int,
    message: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": code,
            "message": message,
            "data": {"raw_content_forwarded": False},
        },
    }
    return JSONResponse(payload, status_code=status_code, headers=headers)


def _sse_fail_closed_event() -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32002,
            "message": "K-Guard closed an invalid or unsafe SSE stream",
            "data": {"raw_content_forwarded": False},
        },
    }
    return b"event: message\ndata: " + _dump_json(payload) + b"\n\n"


def _raw_header_values(request: Request, name: str) -> list[str]:
    target = name.lower().encode("ascii")
    return [value.decode("latin-1") for key, value in request.scope.get("headers", []) if key.lower() == target]


def _safe_response_headers(response: httpx.Response) -> tuple[dict[str, str], str | None]:
    headers: dict[str, str] = {}
    content_type = response.headers.get("content-type")
    if content_type:
        headers["Content-Type"] = content_type
    sessions = response.headers.get_list("mcp-session-id")
    if len(sessions) > 1:
        raise _UpstreamFailure(502, "duplicate_upstream_session_headers", "Upstream repeated the session header")
    session = sessions[0] if sessions else None
    if session:
        if (
            len(session.encode("latin-1")) > 16 * 1024
            or "," in session
            or any(item in session for item in ("\x00", "\r", "\n"))
        ):
            raise _UpstreamFailure(502, "invalid_upstream_session_headers", "Upstream session header is invalid")
        headers["Mcp-Session-Id"] = session
    return headers, session


def _media_type(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _validate_upstream_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("upstream_url must be a fixed HTTP(S) URL")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("upstream_url is invalid") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("upstream_url must be a fixed HTTP(S) URL without credentials or a fragment")
    return value


def _parse_origin_pattern(value: str) -> tuple[str, str, int | None, bool]:
    wildcard_port = value.endswith(":*")
    candidate = value[:-2] if wildcard_port else value
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("allowed origin is invalid") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("allowed origin must be an HTTP(S) origin")
    if wildcard_port and port is not None:
        raise ValueError("wildcard origin cannot also specify a port")
    effective_port = port if port is not None else (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), effective_port, wildcard_port


def _origin_allowed(origin: str, patterns: Iterable[str]) -> bool:
    try:
        scheme, host, port, _ = _parse_origin_pattern(origin)
    except ValueError:
        return False
    for pattern in patterns:
        allowed_scheme, allowed_host, allowed_port, wildcard = _parse_origin_pattern(pattern)
        if scheme == allowed_scheme and host == allowed_host and (wildcard or port == allowed_port):
            return True
    return False


__all__ = [
    "DEFAULT_ALLOWED_ORIGINS",
    "McpHttpProxySettings",
    "create_app",
    "create_mcp_http_proxy_app",
    "get_mcp_http_proxy_report",
    "mcp_http_proxy_toolchain_contract",
]
