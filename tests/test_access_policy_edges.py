from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import k_guard_mcp.access_policy as access


KEY = b"edge-contract-signing-key-at-least-32-bytes-2026"


def _role() -> access.RolePolicy:
    return access.RolePolicy(
        methods=("tools/list", "tools/call"),
        tools=("safe.echo", "repo/*"),
        resources=("config://status",),
        max_calls=5,
    )


def _policy() -> access.AccessPolicy:
    return access.AccessPolicy(
        issuer="issuer.example.test",
        audience="k-guard",
        max_ttl_seconds=60,
        roles={"reviewer": _role()},
        source_sha256="a" * 64,
    )


def _decision(**changes: Any) -> access.AccessDecision:
    values: dict[str, Any] = {
        "allowed": False,
        "reason": "grant_invalid",
        "token_ref": "a" * 64,
        "decision_ref": "b" * 64,
    }
    values.update(changes)
    return access.AccessDecision(**values)


def test_role_and_policy_value_objects_reject_forged_states() -> None:
    with pytest.raises(access.PolicyLoadError, match="policy_tools_invalid"):
        access.RolePolicy(methods=(), tools=("*",), resources=(), max_calls=1)
    with pytest.raises(access.PolicyLoadError, match="policy_max_calls_invalid"):
        access.RolePolicy(methods=(), tools=(), resources=(), max_calls=0)

    policy = _policy()
    invalid = (
        {"schema": "wrong"},
        {"max_ttl_seconds": 0},
        {"roles": {}},
        {"roles": {"bad role": _role()}},
        {"roles": {"reviewer": object()}},
        {"source_sha256": "short"},
    )
    for changes in invalid:
        with pytest.raises(access.PolicyLoadError):
            replace(policy, **changes)


def test_access_decision_rejects_raw_or_invalid_fields_and_serializes_optional_fields() -> None:
    valid = _decision(
        grant_ref="c" * 64,
        role_refs=("d" * 64,),
        calls_used=0,
        visible_tool_count=2,
    )
    assert valid.action == "deny"
    assert valid.authorized is False
    assert valid.as_dict()["visible_tool_count"] == 2
    invalid = (
        {"schema": "wrong"},
        {"allowed": 1},
        {"reason": "not-a-reason"},
        {"token_ref": "short"},
        {"grant_ref": "short"},
        {"role_refs": ("short",)},
        {"calls_used": -1},
    )
    for changes in invalid:
        with pytest.raises(ValueError):
            _decision(**changes)


def test_policy_loader_rejects_bound_json_encoding_and_path_errors(tmp_path: Path) -> None:
    with pytest.raises(access.PolicyLoadError, match="policy_size_bound_invalid"):
        access.load_policy(tmp_path / "missing.json", max_bytes=0)
    with pytest.raises(access.PolicyLoadError, match="policy_path_invalid"):
        access.load_policy(None)  # type: ignore[arg-type]

    invalid_json = tmp_path / "nan.json"
    invalid_json.write_text('{"value":NaN}', encoding="ascii")
    with pytest.raises(access.PolicyLoadError, match="policy_json_invalid"):
        access.load_policy(invalid_json)

    invalid_encoding = tmp_path / "encoding.json"
    invalid_encoding.write_bytes(b"\xff")
    with pytest.raises(access.PolicyLoadError, match="policy_json_invalid"):
        access.load_policy(invalid_encoding)

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(access.PolicyLoadError, match="policy_size_invalid"):
        access.load_policy(empty)

    with pytest.raises(access.PolicyLoadError, match=r"policy_(?:path_not_file|read_failed)"):
        access.load_policy(tmp_path)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"ttl_seconds": 0}, "grant_ttl_invalid"),
        ({"not_before_seconds": 60}, "grant_nbf_invalid"),
        ({"max_calls": 6}, "grant_max_calls_invalid"),
        ({"now": -1}, "grant_iat_invalid"),
    ],
)
def test_grant_minting_rejects_invalid_time_and_budget_claims(changes: dict[str, Any], code: str) -> None:
    values: dict[str, Any] = {
        "subject": "agent@example.test",
        "roles": "reviewer",
        "purpose": "review-1",
        "app_id": "app-1",
        "session_id": "session-1",
        "methods": ["tools/call"],
        "tools": ["safe.echo"],
        "resources": [],
        "ttl_seconds": 60,
        "max_calls": 5,
    }
    values.update(changes)
    with pytest.raises(access.GrantValidationError, match=code):
        access.mint_grant(_policy(), KEY, **values)


def test_grant_minting_and_controller_configuration_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(access.GrantValidationError, match="policy_required"):
        access.mint_grant(object(), KEY, subject="x", roles="x", purpose="x", app_id="x", session_id="x", methods=(), tools=(), resources=(), ttl_seconds=1, max_calls=1)  # type: ignore[arg-type]

    monkeypatch.setattr(access.jwt, "encode", lambda *_args, **_kwargs: "x" * (access.MAX_TOKEN_BYTES + 1))
    with pytest.raises(access.GrantValidationError, match="minted_grant_invalid"):
        access.mint_grant(
            _policy(),
            KEY,
            subject="agent",
            roles="reviewer",
            purpose="review",
            app_id="app",
            session_id="session",
            methods=["tools/call"],
            tools=["safe.echo"],
            resources=[],
            ttl_seconds=10,
            max_calls=1,
        )

    with pytest.raises(access.PolicyLoadError, match="policy_required"):
        access.AccessPolicyController(object(), KEY, app_id="app", session_id="session")  # type: ignore[arg-type]
    with pytest.raises(access.AuditLogError, match="audit_key_without_path"):
        access.AccessPolicyController(_policy(), KEY, app_id="app", session_id="session", audit_key=KEY)

    controller = access.AccessPolicyController(_policy(), KEY, app_id="app", session_id="session")
    with pytest.raises(access.GrantValidationError, match="purpose_required"):
        controller.mint_grant(subject="agent", roles="reviewer", methods=(), tools=(), resources=(), ttl_seconds=10, max_calls=1)


def test_scope_and_identity_helpers_reject_ambiguous_values() -> None:
    assert access._grant_roles("reviewer") == ("reviewer",)
    for value in ([], ["reviewer", "reviewer"], ["bad role"]):
        with pytest.raises(access.GrantValidationError, match="grant_roles_invalid"):
            access._grant_roles(value)

    for value in ("not-a-list", ["duplicate", "duplicate"], ["*"], [" bad"]):
        with pytest.raises(access.GrantValidationError):
            access._scope_list(value, "scope_invalid")
    assert access._valid_scope_pattern("repo/*") is True
    assert access._valid_scope_pattern("repo/read") is True
    assert access._valid_scope_pattern("/*") is False
    assert access._valid_scope_pattern("repo/*/bad") is False
    assert access._valid_scope_pattern("bad\x00") is False

    assert access._pattern_is_subset("repo/read", "repo/*") is True
    assert access._pattern_is_subset("repo/sub/*", "repo/*") is True
    assert access._pattern_is_subset("repo/read", "safe.echo") is False
    assert access._matches_scope("repo/read", ("repo/*",)) is True
    assert access._valid_client_message({"jsonrpc": "2.0", "method": "tools/list"}) is True
    assert access._valid_client_message({"jsonrpc": "1.0", "method": "tools/list"}) is False
    assert access._runtime_value(" bad") is False
    assert access._runtime_value("bad\x00") is False

    for value in (None, "", " bad", "bad\x00", "x" * (access.MAX_IDENTITY_VALUE_BYTES + 1)):
        with pytest.raises(access.GrantValidationError):
            access._identity_text(value, "identity_invalid")


def test_key_json_path_and_response_helpers_cover_error_contracts(tmp_path: Path) -> None:
    assert access._normalize_key(KEY.decode("ascii"), "key") == KEY
    assert access._normalize_key(bytearray(KEY), "key") == KEY
    assert access._normalize_key(memoryview(KEY), "key") == KEY
    with pytest.raises(access.SigningKeyError, match="key_missing"):
        access._normalize_key(object(), "key")
    with pytest.raises(access.SigningKeyError, match="key_weak"):
        access._normalize_key(b"short", "key")

    with pytest.raises(access.AuditLogError, match="canonical_json_invalid"):
        access._canonical_json({"value": float("nan")})
    with pytest.raises(access.AccessPolicyError, match="path_invalid"):
        access._coerce_path("bad\x00path", "path_invalid")
    with pytest.raises(ValueError):
        access._reject_duplicate_keys([("a", 1), ("a", 2)])
    with pytest.raises(ValueError, match="non-finite"):
        access._reject_json_constant("NaN")

    assert access._copy_tools_response(None)["result"]["tools"] == []
    assert access._copy_tools_response({"result": {"tools": [1]}})["result"]["tools"] == [1]
    assert access._empty_tools_response({"jsonrpc": "2.0", "id": 1})["result"]["tools"] == []
    assert "result" not in access._empty_tools_response({"error": {"code": -1}})

    missing = tmp_path / "missing.jsonl"
    assert access.verify_audit_log(missing, KEY) is False


def test_audit_log_rejects_invalid_append_and_corrupt_files(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = access.ChainedAuditLog(path, KEY)
    with pytest.raises(access.AuditLogError, match="audit_decision_invalid"):
        log.append_decision(object())  # type: ignore[arg-type]
    with pytest.raises(access.AuditLogError, match="audit_timestamp_invalid"):
        log.append_decision(_decision(), recorded_at=-1)

    path.write_bytes(b"")
    assert access._inspect_audit_file(path, log._key, missing_ok=False) == (0, "0" * 64, 0)
    path.write_bytes(b"{}")
    with pytest.raises(access.AuditLogError, match="audit_truncated"):
        access._inspect_audit_file(path, log._key, missing_ok=False)
    path.write_bytes(b"not-json\n")
    with pytest.raises(access.AuditLogError, match="audit_json_invalid"):
        access._inspect_audit_file(path, log._key, missing_ok=False)
    path.write_bytes(b"{}\n")
    with pytest.raises(access.AuditLogError, match="audit_record_invalid"):
        access._inspect_audit_file(path, log._key, missing_ok=False)

    directory = tmp_path / "audit-dir"
    directory.mkdir()
    with pytest.raises(access.AuditLogError, match="audit_path_invalid"):
        access._inspect_audit_file(directory, log._key, missing_ok=False)


def test_decision_payload_validator_rejects_each_sensitive_shape() -> None:
    payload = _decision(role_refs=("c" * 64,), calls_used=0).to_dict()
    assert access._valid_decision_payload(payload) is True

    mutations = (
        {"schema": "wrong"},
        {"action": "allow"},
        {"token_ref": "short"},
        {"grant_ref": "short"},
        {"role_refs": "not-a-list"},
        {"calls_used": -1},
        {"unexpected": True},
    )
    for mutation in mutations:
        changed = dict(payload)
        changed.update(mutation)
        assert access._valid_decision_payload(changed) is False
