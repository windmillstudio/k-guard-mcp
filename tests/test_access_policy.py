from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import jwt
import pytest

from k_guard_mcp.access_policy import (
    POLICY_SCHEMA,
    AccessDecision,
    AccessPolicy,
    AccessPolicyController,
    GrantValidationError,
    PolicyLoadError,
    SigningKeyError,
    load_policy,
    verify_audit_log,
)


SIGNING_KEY = b"k-guard-access-test-key-32-bytes-minimum-2026"
OTHER_KEY = b"different-access-test-key-32-bytes-minimum-2026"
APP_ID = "isolated-review-agent"
SESSION_ID = "mcp-session-7f9a"
PURPOSE = "review-ticket-4815"
SUBJECT = "agent.person@example.test"


def _policy_value() -> dict[str, Any]:
    return {
        "schema": POLICY_SCHEMA,
        "issuer": "https://issuer.example.test/k-guard",
        "audience": "k-guard-mcp-proxy",
        "max_ttl_seconds": 120,
        "roles": {
            "reviewer": {
                "methods": ["tools/list", "tools/call", "resources/read", "initialize"],
                "tools": ["safe.echo", "repo/*"],
                "resources": ["file:///workspace/public/*", "config://status"],
                "max_calls": 50,
            },
            "status-only": {
                "methods": ["resources/read"],
                "tools": [],
                "resources": ["config://status"],
                "max_calls": 3,
            },
        },
    }


def _write_policy(path: Path, value: dict[str, Any] | None = None) -> Path:
    path.write_text(
        json.dumps(value or _policy_value(), ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def policy(tmp_path: Path) -> AccessPolicy:
    return load_policy(_write_policy(tmp_path / "access-policy.json"))


@pytest.fixture
def controller(policy: AccessPolicy) -> AccessPolicyController:
    return AccessPolicyController(
        policy,
        SIGNING_KEY,
        app_id=APP_ID,
        session_id=SESSION_ID,
        purpose=PURPOSE,
    )


def _grant(
    controller: AccessPolicyController,
    *,
    methods: list[str] | None = None,
    tools: list[str] | None = None,
    resources: list[str] | None = None,
    max_calls: int = 10,
    now: int | None = None,
    not_before_seconds: int = 0,
) -> str:
    return controller.mint_grant(
        subject=SUBJECT,
        roles=["reviewer"],
        methods=methods if methods is not None else ["tools/list", "tools/call", "resources/read"],
        tools=tools if tools is not None else ["safe.echo", "repo/*"],
        resources=resources if resources is not None else ["file:///workspace/public/*", "config://status"],
        ttl_seconds=60,
        max_calls=max_calls,
        now=now,
        not_before_seconds=not_before_seconds,
    )


def _claims(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


def _resign(token: str, *, key: bytes = SIGNING_KEY, **updates: Any) -> str:
    claims = _claims(token)
    claims.update(updates)
    return jwt.encode(claims, key, algorithm="HS256", headers={"typ": "JWT"})


def _tool_call(name: str = "safe.echo", *, marker: str = "raw-tool-argument-secret") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": {"marker": marker}},
    }


def _resource_read(uri: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/read",
        "params": {"uri": uri},
    }


def test_policy_loader_is_strict_bounded_duplicate_rejecting_and_no_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_policy(tmp_path / "policy.json")
    loaded = load_policy(path)
    assert loaded.schema == POLICY_SCHEMA
    assert loaded.max_ttl_seconds == 120
    assert set(loaded.roles) == {"reviewer", "status-only"}

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema":"k_guard_agent_access_policy.v1","issuer":"a","issuer":"b",'
        '"audience":"c","max_ttl_seconds":60,"roles":{}}',
        encoding="utf-8",
    )
    with pytest.raises(PolicyLoadError, match="policy_duplicate_json_key"):
        load_policy(duplicate)

    with pytest.raises(PolicyLoadError, match="policy_size_invalid"):
        load_policy(path, max_bytes=16)

    missing_key_policy = _policy_value()
    missing_key_policy.pop("audience")
    missing_key = _write_policy(tmp_path / "missing-key.json", missing_key_policy)
    with pytest.raises(PolicyLoadError, match="policy_schema_invalid"):
        load_policy(missing_key)

    wildcard_policy = _policy_value()
    wildcard_policy["roles"]["reviewer"]["tools"] = ["*"]
    wildcard = _write_policy(tmp_path / "wildcard.json", wildcard_policy)
    with pytest.raises(PolicyLoadError, match="policy_tools_invalid"):
        load_policy(wildcard)

    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == path.absolute() or original_is_symlink(self),
    )
    with pytest.raises(PolicyLoadError, match="policy_symlink_disallowed"):
        load_policy(path)


def test_missing_and_short_signing_keys_are_rejected(policy: AccessPolicy) -> None:
    with pytest.raises(SigningKeyError, match="signing_key_missing"):
        AccessPolicyController(policy, None, app_id=APP_ID, session_id=SESSION_ID)  # type: ignore[arg-type]
    with pytest.raises(SigningKeyError, match="signing_key_weak"):
        AccessPolicyController(policy, b"short", app_id=APP_ID, session_id=SESSION_ID)


def test_happy_path_decision_and_controller_summary_are_raw_free(
    controller: AccessPolicyController,
) -> None:
    token = _grant(controller)
    message = _tool_call()
    decision = controller.authorize(token, message)
    assert decision.allowed is True
    assert decision.reason == "authorized"
    assert decision.raw_free is True
    assert decision.calls_used == 1
    assert decision.max_calls == 10
    assert len(decision.subject_ref) == 64
    assert len(decision.target_ref) == 64

    report_text = json.dumps(
        {"decision": decision.to_dict(), "summary": controller.controller_summary()},
        sort_keys=True,
    )
    for raw in (
        token,
        SUBJECT,
        APP_ID,
        SESSION_ID,
        PURPOSE,
        "safe.echo",
        "raw-tool-argument-secret",
        SIGNING_KEY.decode("ascii"),
    ):
        assert raw not in report_text
    assert '"raw_returned": false' in report_text
    assert '"raw_free": true' in report_text
    assert "_ref" in report_text


def test_grant_authentication_binds_identity_without_consuming_call_budget(
    controller: AccessPolicyController,
) -> None:
    token = _grant(controller, max_calls=1)

    authenticated = controller.authenticate_grant(token)
    authorized = controller.authorize(token, _tool_call())

    assert authenticated.allowed is True
    assert authenticated.reason == "authenticated"
    assert authenticated.calls_used is None
    assert authenticated.subject_ref == authorized.subject_ref
    assert authorized.calls_used == 1


def test_tampering_expiry_nbf_and_ttl_are_denied(controller: AccessPolicyController) -> None:
    token = _grant(controller)

    tampered = _resign(token, key=OTHER_KEY)
    assert controller.authorize(tampered, _tool_call()).reason == "grant_signature_invalid"

    expired = _grant(controller, now=int(time.time()) - 180)
    assert controller.authorize(expired, _tool_call()).reason == "grant_expired"

    not_yet_valid = _grant(controller, not_before_seconds=30)
    assert controller.authorize(not_yet_valid, _tool_call()).reason == "grant_not_yet_valid"

    claims = _claims(token)
    ttl_exceeded = _resign(token, exp=claims["iat"] + controller.policy.max_ttl_seconds + 1)
    assert controller.authorize(ttl_exceeded, _tool_call()).reason == "grant_ttl_exceeded"

    claims.pop("sub")
    missing_claim = jwt.encode(claims, SIGNING_KEY, algorithm="HS256", headers={"typ": "JWT"})
    assert controller.authorize(missing_claim, _tool_call()).reason == "grant_claims_invalid"


@pytest.mark.parametrize(
    ("claim", "value", "reason"),
    [
        ("iss", "https://wrong-issuer.example.test", "grant_issuer_mismatch"),
        ("aud", "wrong-audience", "grant_audience_mismatch"),
        ("app_id", "wrong-app", "grant_app_id_mismatch"),
        ("session_id", "wrong-session", "grant_session_mismatch"),
        ("purpose", "wrong-purpose", "grant_purpose_mismatch"),
    ],
)
def test_grant_identity_bindings_are_validated(
    controller: AccessPolicyController,
    claim: str,
    value: str,
    reason: str,
) -> None:
    token = _grant(controller)
    denied = controller.authorize(_resign(token, **{claim: value}), _tool_call())
    assert denied.allowed is False
    assert denied.reason == reason


def test_unknown_role_and_scope_escalation_are_denied(controller: AccessPolicyController) -> None:
    token = _grant(controller)
    unknown_role = _resign(token, roles=["administrator"])
    assert controller.authorize(unknown_role, _tool_call()).reason == "grant_role_unknown"

    escalated = _resign(token, tools=["safe.echo", "admin.delete"])
    assert controller.authorize(escalated, _tool_call()).reason == "grant_scope_escalation"

    broad = _resign(token, tools=["*"])
    assert controller.authorize(broad, _tool_call()).reason == "tools_claim_invalid"

    with pytest.raises(GrantValidationError, match="grant_scope_escalation"):
        controller.mint_grant(
            subject=SUBJECT,
            roles=["reviewer"],
            methods=["tools/call"],
            tools=["admin.delete"],
            resources=[],
            ttl_seconds=60,
            max_calls=1,
        )


def test_default_deny_exact_and_trailing_prefix_scope_for_tools_and_resources(
    controller: AccessPolicyController,
) -> None:
    token = _grant(controller, max_calls=10)

    assert controller.authorize(token, _tool_call("safe.echo")).allowed is True
    assert controller.authorize(token, _tool_call("repo/read")).allowed is True
    assert controller.authorize(token, _tool_call("safe.echo/child")).reason == "tool_denied"
    assert controller.authorize(token, _tool_call("admin.delete")).reason == "tool_denied"

    public_uri = "file:///workspace/public/report.json"
    private_uri = "file:///workspace/private/secret.json"
    assert controller.authorize(token, _resource_read(public_uri)).allowed is True
    assert controller.authorize(token, _resource_read(private_uri)).reason == "resource_denied"
    assert controller.authorize(token, _resource_read("file:///workspace/public")).reason == "resource_denied"

    denied_method = {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}}
    assert controller.authorize(token, denied_method).reason == "method_denied"
    assert controller.authorize(token, [denied_method]).reason == "jsonrpc_message_invalid"


def test_per_grant_call_budget_is_fail_closed(controller: AccessPolicyController) -> None:
    token = _grant(controller, max_calls=2)
    first = controller.authorize(token, _tool_call())
    second = controller.authorize(token, _resource_read("config://status"))
    exhausted = controller.authorize(token, _tool_call("repo/read"))

    assert (first.calls_used, second.calls_used) == (1, 2)
    assert exhausted.allowed is False
    assert exhausted.reason == "call_budget_exhausted"
    assert exhausted.calls_used == 2


def test_tools_list_response_is_filtered_without_mutating_transport_input(
    controller: AccessPolicyController,
) -> None:
    token = _grant(controller, methods=["tools/list"], resources=[], max_calls=4)
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "safe.echo", "description": "allowed exact"},
                {"name": "repo/read", "description": "allowed prefix"},
                {"name": "admin.delete", "description": "hidden"},
                {"description": "missing name"},
            ],
            "nextCursor": "opaque-cursor",
        },
    }
    filtered = controller.filter_tools_list_response(token, response)

    assert [tool["name"] for tool in filtered["result"]["tools"]] == ["safe.echo", "repo/read"]
    assert len(response["result"]["tools"]) == 4
    assert filtered["result"]["nextCursor"] == "opaque-cursor"

    invalid_grant = _resign(token, key=OTHER_KEY)
    assert controller.filter_tools_list(invalid_grant, response)["result"]["tools"] == []


def test_audit_chain_hmac_tamper_detection_and_raw_free_log(
    policy: AccessPolicy,
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "access-audit.jsonl"
    controller = AccessPolicyController(
        policy,
        SIGNING_KEY,
        app_id=APP_ID,
        session_id=SESSION_ID,
        purpose=PURPOSE,
        audit_path=audit_path,
    )
    token = _grant(controller, max_calls=4)
    secret_uri = "file:///workspace/private/very-secret-record.json"
    controller.authorize(token, _tool_call(marker="audit-argument-secret"))
    controller.authorize(token, _resource_read(secret_uri))

    assert verify_audit_log(audit_path, SIGNING_KEY) is True
    assert verify_audit_log(audit_path, OTHER_KEY) is False
    lines = audit_path.read_text(encoding="ascii").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["previous_sha256"] == json.loads(lines[0])["entry_sha256"]

    raw_log = audit_path.read_text(encoding="ascii")
    for raw in (
        token,
        SUBJECT,
        PURPOSE,
        APP_ID,
        SESSION_ID,
        secret_uri,
        "audit-argument-secret",
        SIGNING_KEY.decode("ascii"),
    ):
        assert raw not in raw_log

    record = json.loads(lines[0])
    record["decision"]["reason"] = "tampered"
    lines[0] = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    audit_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    assert verify_audit_log(audit_path, SIGNING_KEY) is False


def test_public_decision_type_rejects_non_reference_raw_values() -> None:
    with pytest.raises(ValueError, match="primary references"):
        AccessDecision(
            allowed=False,
            reason="grant_invalid",
            token_ref="raw-token-must-not-enter-audit",
            decision_ref="0" * 64,
        )


def test_call_budget_is_atomic_under_concurrency(controller: AccessPolicyController) -> None:
    max_calls = 17
    token = _grant(controller, max_calls=max_calls)
    message = _tool_call()

    with ThreadPoolExecutor(max_workers=24) as pool:
        decisions = list(pool.map(lambda _: controller.authorize(token, message), range(100)))

    allowed = [decision for decision in decisions if decision.allowed]
    denied = [decision for decision in decisions if not decision.allowed]
    assert len(allowed) == max_calls
    assert sorted(decision.calls_used for decision in allowed if decision.calls_used is not None) == list(
        range(1, max_calls + 1)
    )
    assert len(denied) == 100 - max_calls
    assert {decision.reason for decision in denied} == {"call_budget_exhausted"}
    assert controller.summary()["active_grant_calls_consumed"] == max_calls
