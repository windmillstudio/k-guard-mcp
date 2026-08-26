from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any, Callable

import anyio
import httpx
import pytest

from k_guard_mcp.access_policy import AccessPolicyController, load_policy, verify_audit_log
from k_guard_mcp.hashing import DEFAULT_EVIDENCE_KEY
from k_guard_mcp.mcp_http_proxy import (
    McpHttpProxySettings,
    create_mcp_http_proxy_app,
    get_mcp_http_proxy_report,
)
from k_guard_mcp.mcp_proxy import run_stdio_proxy
from k_guard_mcp.provenance import verify_evidence_bundle
from k_guard_mcp.runtime_mediation_receipts import (
    RECEIPT_FIELD_SET,
    RECEIPT_SCHEMA,
    RuntimeMediationReceiptChain,
    inspect_runtime_mediation_receipt_tamper,
    new_transaction_id,
    policy_ref_for,
    receipt_semantic_projection,
    verify_proxy_report_receipts,
    verify_runtime_mediation_receipts,
)


SECRET = "sk-thisisaverylongfakeapikey000"
PII_EMAIL = "alice@example.com"
OPERATOR_KEY = "k-guard-operator-receipt-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
POST_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
SIGNING_KEY = b"k-guard-proxy-integration-key-32-bytes-minimum-2026"


def _tool_call(request_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _echo_upstream(path: Path) -> Path:
    path.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'received':True,'echo':request.get('params',{})}}), flush=True)\n",
        encoding="utf-8",
    )
    return path


def _run_stdio(
    tmp_path: Path,
    messages: list[dict[str, Any]],
    *,
    receipt_log_path: Path | None = None,
    access_controller: AccessPolicyController | None = None,
    access_token: str | None = None,
) -> tuple[int, dict[str, Any], str]:
    upstream = _echo_upstream(tmp_path / "upstream.py")
    report_path = tmp_path / "stdio-report.json"
    protocol = io.StringIO()
    client_input = io.StringIO("\n".join(json.dumps(item) for item in messages) + "\n")
    code = run_stdio_proxy(
        [sys.executable, "-u", str(upstream)],
        report_path=report_path,
        client_input=client_input,
        protocol_output=protocol,
        diagnostic_output=io.StringIO(),
        access_controller=access_controller,
        access_token=access_token,
        receipt_log_path=receipt_log_path,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return code, report, protocol.getvalue()


async def _http_exchange(
    handler: Callable[[httpx.Request], httpx.Response],
    payload: dict[str, Any],
    *,
    settings: McpHttpProxySettings | None = None,
    access_controller: AccessPolicyController | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[Any, httpx.Response, int]:
    calls = {"count": 0}

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return handler(request)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(wrapped), follow_redirects=True)
    app = create_mcp_http_proxy_app(
        "http://upstream.test/mcp",
        settings,
        http_client=upstream,
        access_controller=access_controller,
    )
    downstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test")
    try:
        response = await downstream.post("/mcp", headers=headers or POST_HEADERS, json=payload)
        return app, response, calls["count"]
    finally:
        await downstream.aclose()
        await upstream.aclose()


def _controller(tmp_path: Path) -> AccessPolicyController:
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
                        "methods": ["initialize", "tools/list", "tools/call"],
                        "tools": ["safe.echo", "publish"],
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
        SIGNING_KEY,
        app_id="app-one",
        session_id="review-session",
        purpose="release-review",
        audit_path=tmp_path / "access-audit.jsonl",
    )


def _assert_receipt_shape(receipt: dict[str, Any]) -> None:
    assert set(receipt) == RECEIPT_FIELD_SET
    assert receipt["schema"] == RECEIPT_SCHEMA
    assert receipt["raw_free"] is True
    assert receipt["raw_returned"] is False
    assert receipt["action"] in {"allow", "redact", "block", "deny"}
    assert isinstance(receipt["original_forwarded"], bool)
    assert isinstance(receipt["safe_replacement_forwarded"], bool)
    assert not (receipt["original_forwarded"] and receipt["safe_replacement_forwarded"])


def _assert_raw_free(blob: str, *needles: str) -> None:
    for needle in needles:
        assert needle not in blob


def test_chain_records_raw_free_hmac_receipts_and_detects_tamper(tmp_path: Path) -> None:
    persist = tmp_path / "receipts.jsonl"
    chain = RuntimeMediationReceiptChain(
        transport="jsonl",
        toolchain_ref="a" * 64,
        policy_ref=policy_ref_for(),
        persist_path=persist,
        hmac_key=DEFAULT_EVIDENCE_KEY,
    )
    first = chain.record(
        direction="client_to_upstream",
        action="allow",
        message=_tool_call(1, "echo", {"text": "ok"}),
        original_forwarded=True,
        safe_replacement_forwarded=False,
    )
    second = chain.record(
        direction="upstream_to_client",
        action="block",
        message={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        transaction_id=first["transaction_id"],
        original_forwarded=False,
        safe_replacement_forwarded=False,
    )
    _assert_receipt_shape(first)
    _assert_receipt_shape(second)
    assert first["transaction_id"] == second["transaction_id"]
    assert first["transaction_id"] != "1"
    assert second["previous_sha256"] == first["entry_sha256"]
    exported = chain.export()
    assert exported["hmac"]["key_mode"] == "public-default-key"
    assert exported["hmac"]["tamper_resistant_with_operator_secret"] is False
    assert verify_runtime_mediation_receipts(chain.receipts(), hmac_key=DEFAULT_EVIDENCE_KEY) is True
    lines = persist.read_text(encoding="ascii").splitlines()
    record = json.loads(lines[0])
    record["action"] = "deny"
    persist.write_text(json.dumps(record) + "\n" + lines[1] + "\n", encoding="ascii")
    tampered = [json.loads(line) for line in persist.read_text(encoding="ascii").splitlines()]
    assert verify_runtime_mediation_receipts(tampered, hmac_key=DEFAULT_EVIDENCE_KEY) is False
    report = inspect_runtime_mediation_receipt_tamper(tampered, hmac_key=DEFAULT_EVIDENCE_KEY)
    assert report["tampered"] is True
    assert report["tamper_resistant_with_operator_secret"] is False


def test_emitted_receipt_matches_published_draft_2020_12_schema(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "k_guard_mcp"
        / "schemas"
        / "k-guard-runtime-mediation-receipt-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    receipt = RuntimeMediationReceiptChain(transport="jsonl", toolchain_ref="d" * 64).record(
        direction="client_to_upstream",
        action="block",
        message=_tool_call(5, "publish", {"token": SECRET}),
        findings=[{"id": "finding-1", "rule_id": "SECRET_OPENAI_STYLE_KEY"}],
        original_forwarded=False,
        safe_replacement_forwarded=False,
    )
    jsonschema.Draft202012Validator(schema).validate(receipt)


def test_operator_key_boundary_is_explicit_and_public_default_is_not_tamper_resistant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)
    public_chain = RuntimeMediationReceiptChain(transport="jsonl", toolchain_ref="b" * 64)
    public_chain.record(
        direction="client_to_upstream",
        action="allow",
        message=_tool_call(3, "echo", {"text": "ok"}),
        original_forwarded=True,
        safe_replacement_forwarded=False,
    )
    public_export = public_chain.export()
    assert public_export["hmac"]["key_mode"] == "public-default-key"
    assert public_export["hmac"]["tamper_resistant_with_operator_secret"] is False
    forged = json.loads(json.dumps(public_chain.receipts()[0]))
    forged["action"] = "block"
    forged["original_forwarded"] = False
    payload = {key: forged[key] for key in forged if key not in {"entry_sha256", "chain_hmac_sha256"}}
    import hashlib
    import hmac

    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    entry = hashlib.sha256(canonical).hexdigest()
    derived = hmac.new(DEFAULT_EVIDENCE_KEY.encode("utf-8"), b"k-guard-runtime-mediation-receipt-v1\0chain", hashlib.sha256).digest()
    forged["entry_sha256"] = entry
    forged["chain_hmac_sha256"] = hmac.new(
        derived,
        b"k-guard-runtime-mediation-receipt-v1\0" + (b"0" * 64) + b"\0" + entry.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert verify_runtime_mediation_receipts([forged], hmac_key=DEFAULT_EVIDENCE_KEY) is True

    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    operator_chain = RuntimeMediationReceiptChain(transport="jsonl", toolchain_ref="c" * 64)
    operator_chain.record(
        direction="client_to_upstream",
        action="allow",
        message=_tool_call(4, "echo", {"text": "ok"}),
        original_forwarded=True,
        safe_replacement_forwarded=False,
    )
    operator_export = operator_chain.export()
    assert operator_export["hmac"]["key_mode"] == "operator-keyed"
    assert operator_export["hmac"]["tamper_resistant_with_operator_secret"] is True
    assert verify_runtime_mediation_receipts(operator_chain.receipts()) is True
    assert verify_runtime_mediation_receipts(operator_chain.receipts(), hmac_key=DEFAULT_EVIDENCE_KEY) is False
    assert verify_runtime_mediation_receipts([forged]) is False


def test_stdio_attack_block_is_raw_free_and_not_forwarded_upstream(tmp_path: Path) -> None:
    code, report, protocol = _run_stdio(tmp_path, [_tool_call(21, "publish", {"token": SECRET})])
    receipts = report["mediation_receipts"]["receipts"]
    client_receipts = [item for item in receipts if item["direction"] == "client_to_upstream"]
    assert code == 0
    assert client_receipts
    assert client_receipts[0]["action"] == "block"
    assert client_receipts[0]["original_forwarded"] is False
    assert "SECRET_OPENAI_STYLE_KEY" in client_receipts[0]["rule_ids"]
    assert report["stats"]["client_messages_dropped"] == 1
    assert report["stats"].get("client_lines_forwarded", 0) == 0
    assert verify_proxy_report_receipts(report) is True
    assert verify_evidence_bundle(report["evidence_bundle"]) is True
    blob = json.dumps(report) + protocol
    _assert_raw_free(blob, SECRET)
    for receipt in receipts:
        _assert_receipt_shape(receipt)
        assert receipt["transaction_id"] not in protocol


def test_stdio_benign_allow_and_pii_redact_share_transaction_ids(tmp_path: Path) -> None:
    code, report, protocol = _run_stdio(
        tmp_path,
        [
            _tool_call(7, "echo", {"text": "hello"}),
            _tool_call(8, "lookup", {"email": PII_EMAIL}),
        ],
    )
    receipts = report["mediation_receipts"]["receipts"]
    by_action = {item["action"]: item for item in receipts if item["direction"] == "client_to_upstream"}
    assert code == 0
    assert by_action["allow"]["original_forwarded"] is True
    assert by_action["allow"]["safe_replacement_forwarded"] is False
    assert by_action["redact"]["original_forwarded"] is False
    assert by_action["redact"]["safe_replacement_forwarded"] is True
    correlated = {}
    for item in receipts:
        correlated.setdefault(item["transaction_id"], []).append(item["direction"])
    assert any(set(directions) == {"client_to_upstream", "upstream_to_client"} for directions in correlated.values())
    _assert_raw_free(json.dumps(report) + protocol, PII_EMAIL)


def test_stdio_receipt_persist_failure_fails_closed_before_upstream(tmp_path: Path) -> None:
    sidecar = tmp_path / "stdio-report.json.receipts.jsonl"
    sidecar.mkdir()
    code, report, protocol = _run_stdio(tmp_path, [_tool_call(9, "echo", {"text": "hello"})])
    assert code == 3
    assert "mediation_receipt_persist_failed" in {item["kind"] for item in report["errors"]}
    assert report["stats"].get("client_lines_forwarded", 0) == 0
    assert protocol == "" or "hello" not in protocol


def test_stdio_explicit_receipt_log_and_access_transaction_binding(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token = controller.mint_grant(
        subject="agent-a",
        roles=["reviewer"],
        methods=["initialize", "tools/list", "tools/call"],
        tools=["safe.echo"],
        resources=[],
        ttl_seconds=60,
        max_calls=20,
    )
    receipt_log = tmp_path / "explicit.receipts.jsonl"
    code, report, protocol = _run_stdio(
        tmp_path,
        [_tool_call(2, "admin.delete", {"x": 1}), _tool_call(3, "safe.echo", {"text": "ok"})],
        receipt_log_path=receipt_log,
        access_controller=controller,
        access_token=token,
    )
    receipts = report["mediation_receipts"]["receipts"]
    deny = next(item for item in receipts if item["action"] == "deny")
    allow = next(item for item in receipts if item["action"] == "allow" and item["direction"] == "client_to_upstream")
    assert code == 0
    assert deny["access_reason"] == "tool_denied"
    assert deny["original_forwarded"] is False
    assert receipt_log.is_file()
    audit_lines = (tmp_path / "access-audit.jsonl").read_text(encoding="ascii").splitlines()
    deny_audit = json.loads(audit_lines[0])["decision"]
    assert deny_audit.get("transaction_ref") == deny["transaction_id"]
    assert allow["transaction_id"] != deny["transaction_id"]
    assert verify_audit_log(tmp_path / "access-audit.jsonl", SIGNING_KEY) is True
    blob = json.dumps(report) + protocol
    _assert_raw_free(blob, token, "agent-a", "admin.delete")


def test_one_operator_keyed_chain_unifies_access_deny_and_content_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    controller = _controller(tmp_path)
    token = controller.mint_grant(
        subject="agent-a",
        roles=["reviewer"],
        methods=["initialize", "tools/list", "tools/call"],
        tools=["safe.echo", "publish"],
        resources=[],
        ttl_seconds=60,
        max_calls=20,
    )
    code, report, protocol = _run_stdio(
        tmp_path,
        [
            _tool_call(41, "admin.delete", {"x": 1}),
            _tool_call(42, "publish", {"token": SECRET}),
        ],
        access_controller=controller,
        access_token=token,
    )
    receipts = report["mediation_receipts"]["receipts"]
    deny = next(item for item in receipts if item["action"] == "deny")
    block = next(item for item in receipts if item["action"] == "block")
    audit_decision = json.loads((tmp_path / "access-audit.jsonl").read_text(encoding="ascii").splitlines()[0])[
        "decision"
    ]

    assert code == 0
    assert report["mediation_receipts"]["hmac"]["key_mode"] == "operator-keyed"
    assert verify_proxy_report_receipts(report, require_operator_key=True) is True
    assert deny["transaction_id"] == audit_decision["transaction_ref"]
    assert block["transaction_id"] != deny["transaction_id"]
    assert block["finding_refs"]
    assert "SECRET_OPENAI_STYLE_KEY" in block["rule_ids"]
    assert deny["original_forwarded"] is False
    assert block["original_forwarded"] is False
    _assert_raw_free(json.dumps(report) + protocol, SECRET, token, "admin.delete")


def test_http_attack_block_never_reaches_upstream_and_correlates_benign_transaction(tmp_path: Path) -> None:
    report_path = tmp_path / "http-report.json"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}},
        )

    async def exercise():
        blocked_app, blocked, blocked_calls = await _http_exchange(
            upstream_handler,
            _tool_call(21, "publish", {"token": SECRET}),
            settings=McpHttpProxySettings(report_path=report_path),
        )
        allowed_app, allowed, allowed_calls = await _http_exchange(
            upstream_handler,
            _tool_call(22, "echo", {"text": "hello"}),
            settings=McpHttpProxySettings(report_path=tmp_path / "http-allow.json"),
        )
        return blocked_app, blocked, blocked_calls, allowed_app, allowed, allowed_calls

    blocked_app, blocked, blocked_calls, allowed_app, allowed, allowed_calls = anyio.run(exercise)
    blocked_report = get_mcp_http_proxy_report(blocked_app)
    allowed_report = get_mcp_http_proxy_report(allowed_app)
    block_receipt = next(
        item
        for item in blocked_report["mediation_receipts"]["receipts"]
        if item["direction"] == "client_to_upstream"
    )
    assert blocked.status_code == 403
    assert blocked_calls == 0
    assert block_receipt["action"] == "block"
    assert block_receipt["original_forwarded"] is False
    assert allowed.status_code == 200
    assert allowed_calls == 1
    txn_map: dict[str, set[str]] = {}
    for item in allowed_report["mediation_receipts"]["receipts"]:
        txn_map.setdefault(item["transaction_id"], set()).add(item["direction"])
    assert {"client_to_upstream", "upstream_to_client"} in txn_map.values()
    assert verify_proxy_report_receipts(blocked_report) is True
    assert verify_evidence_bundle(blocked_report["evidence_bundle"]) is True
    _assert_raw_free(json.dumps(blocked_report) + blocked.text, SECRET)


def test_http_stdio_parity_for_attack_block_and_pii_redact(tmp_path: Path) -> None:
    block_dir = tmp_path / "block"
    redact_dir = tmp_path / "redact"
    block_dir.mkdir()
    redact_dir.mkdir()
    stdio_block_code, stdio_block, _protocol = _run_stdio(block_dir, [_tool_call(21, "publish", {"token": SECRET})])
    stdio_redact_code, stdio_redact, _ = _run_stdio(redact_dir, [_tool_call(22, "lookup", {"email": PII_EMAIL})])

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": payload.get("params", {})},
        )

    async def exercise():
        block_app, _, _ = await _http_exchange(upstream_handler, _tool_call(21, "publish", {"token": SECRET}))
        redact_app, _, _ = await _http_exchange(upstream_handler, _tool_call(22, "lookup", {"email": PII_EMAIL}))
        return get_mcp_http_proxy_report(block_app), get_mcp_http_proxy_report(redact_app)

    http_block, http_redact = anyio.run(exercise)

    def client_projection(report: dict[str, Any]) -> list[dict[str, Any]]:
        receipts = [
            item
            for item in report["mediation_receipts"]["receipts"]
            if item["direction"] == "client_to_upstream" and item["action"] in {"block", "redact"}
        ]
        return receipt_semantic_projection(receipts)

    assert stdio_block_code == 0
    assert stdio_redact_code == 0
    assert client_projection(stdio_block) == client_projection(http_block)
    assert client_projection(stdio_redact) == client_projection(http_redact)
    assert stdio_block["schema"] == "k_guard_mcp_stdio_proxy_report.v1"
    assert http_block["schema"] == "k_guard_mcp_http_proxy_report.v1"
    assert "evidence_bundle" in stdio_block and "evidence_bundle" in http_block


def test_http_receipt_persist_failure_fails_closed_without_upstream(tmp_path: Path) -> None:
    report_path = tmp_path / "http-report.json"
    sidecar = tmp_path / "http-report.json.receipts.jsonl"
    sidecar.mkdir()
    calls = {"count": 0}

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

    async def exercise():
        app, response, _ = await _http_exchange(
            upstream_handler,
            _tool_call(1, "echo", {"text": "hello"}),
            settings=McpHttpProxySettings(report_path=report_path),
        )
        return app, response

    app, response = anyio.run(exercise)
    report = get_mcp_http_proxy_report(app)
    assert response.status_code in {500, 503}
    assert calls["count"] == 0
    assert report["control_status"] == "failed_closed"
    assert "mediation_receipt_persist_failed" in {item["kind"] for item in report["control_errors"]}


def test_http_mixed_batch_receipts_never_claim_unforwarded_message_was_forwarded(tmp_path: Path) -> None:
    calls = {"count": 0}

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(500)

    async def exercise():
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler), follow_redirects=True)
        app = create_mcp_http_proxy_app("http://upstream.test/mcp", http_client=upstream)
        downstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test")
        try:
            response = await downstream.post(
                "/mcp",
                headers=POST_HEADERS,
                json=[
                    _tool_call(31, "echo", {"text": "hello"}),
                    _tool_call(32, "publish", {"token": SECRET}),
                ],
            )
            return app, response
        finally:
            await downstream.aclose()
            await upstream.aclose()

    app, response = anyio.run(exercise)
    receipts = get_mcp_http_proxy_report(app)["mediation_receipts"]["receipts"]
    assert response.status_code == 403
    assert calls["count"] == 0
    assert len(receipts) == 2
    assert all(item["original_forwarded"] is False for item in receipts)
    assert all(item["safe_replacement_forwarded"] is False for item in receipts)
    atomic = next(item for item in receipts if "BATCH_ATOMIC_BLOCK" in item["rule_ids"])
    assert atomic["action"] == "block"


def test_http_access_deny_binds_transaction_ref(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    token = controller.mint_grant(
        subject="agent-a",
        roles=["reviewer"],
        methods=["initialize", "tools/list", "tools/call"],
        tools=["safe.echo"],
        resources=[],
        ttl_seconds=60,
        max_calls=20,
    )

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("denied request must not reach upstream")

    async def exercise():
        return await _http_exchange(
            upstream_handler,
            _tool_call(2, "admin.delete", {"x": 1}),
            access_controller=controller,
            headers={**POST_HEADERS, "Authorization": f"Bearer {token}"},
        )

    _app, response, calls = anyio.run(exercise)
    report = get_mcp_http_proxy_report(_app)
    deny = next(item for item in report["mediation_receipts"]["receipts"] if item["action"] == "deny")
    audit = json.loads((tmp_path / "access-audit.jsonl").read_text(encoding="ascii").splitlines()[-1])
    assert response.status_code == 403
    assert calls == 0
    assert deny["access_reason"] == "tool_denied"
    assert audit["decision"].get("transaction_ref") == deny["transaction_id"]


def test_new_transaction_id_is_non_reversible_random_ref() -> None:
    first = new_transaction_id()
    second = new_transaction_id()
    assert first != second
    assert len(first) == 64
    assert first != "1"
