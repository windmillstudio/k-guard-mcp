"""Fail-closed JIT/JEA grants for isolated MCP agent sessions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import jwt


POLICY_SCHEMA = "k_guard_agent_access_policy.v1"
DECISION_SCHEMA = "k_guard_access_decision.v1"
CONTROLLER_SUMMARY_SCHEMA = "k_guard_access_controller_summary.v1"
AUDIT_SCHEMA = "k_guard_access_audit.v1"

DEFAULT_MAX_POLICY_BYTES = 64 * 1024
HARD_MAX_POLICY_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 32 * 1024
MAX_GRANT_TTL_SECONDS = 15 * 60
MIN_SIGNING_KEY_BYTES = 32
MAX_SIGNING_KEY_BYTES = 16 * 1024
MAX_ROLES = 64
MAX_GRANT_ROLES = 16
MAX_SCOPE_ITEMS = 1024
MAX_SCOPE_VALUE_BYTES = 4096
MAX_IDENTITY_VALUE_BYTES = 1024
MAX_CALLS = 1_000_000
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MAX_AUDIT_LINE_BYTES = 64 * 1024
REF_SCHEME = "hmac-sha256:k-guard-access:v1"

_ROLE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOP_LEVEL_KEYS = frozenset({"schema", "issuer", "audience", "max_ttl_seconds", "roles"})
_ROLE_KEYS = frozenset({"methods", "tools", "resources", "max_calls"})
_REQUIRED_GRANT_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "jti",
        "iat",
        "nbf",
        "exp",
        "roles",
        "purpose",
        "app_id",
        "session_id",
        "methods",
        "tools",
        "resources",
        "max_calls",
    }
)
_AUDIT_RECORD_KEYS = frozenset(
    {
        "schema",
        "sequence",
        "recorded_at",
        "previous_sha256",
        "decision",
        "entry_sha256",
        "chain_hmac_sha256",
    }
)
_DECISION_KEYS = frozenset(
    {
        "schema",
        "allowed",
        "action",
        "reason",
        "token_ref",
        "grant_ref",
        "subject_ref",
        "role_refs",
        "method_ref",
        "target_ref",
        "app_id_ref",
        "session_ref",
        "purpose_ref",
        "transaction_ref",
        "calls_used",
        "max_calls",
        "visible_tool_count",
        "filtered_tool_count",
        "decision_ref",
        "ref_scheme",
        "raw_free",
        "raw_returned",
    }
)
_DECISION_REASONS = frozenset(
    {
        "app_id_invalid",
        "audit_write_failed",
        "authenticated",
        "authorized",
        "call_budget_exhausted",
        "grant_algorithm_invalid",
        "grant_app_id_mismatch",
        "grant_audience_mismatch",
        "grant_claims_invalid",
        "grant_expired",
        "grant_invalid",
        "grant_issuer_mismatch",
        "grant_max_calls_invalid",
        "grant_not_yet_valid",
        "grant_purpose_mismatch",
        "grant_role_unknown",
        "grant_roles_invalid",
        "grant_scope_escalation",
        "grant_session_mismatch",
        "grant_signature_invalid",
        "grant_time_claims_invalid",
        "grant_ttl_exceeded",
        "jti_invalid",
        "jsonrpc_message_invalid",
        "method_denied",
        "methods_claim_invalid",
        "purpose_invalid",
        "resource_denied",
        "resource_read_invalid",
        "resources_claim_invalid",
        "session_id_invalid",
        "subject_invalid",
        "tool_call_invalid",
        "tool_denied",
        "tool_list_filtered",
        "tool_list_response_invalid",
        "tools_claim_invalid",
    }
)
_INITIAL_AUDIT_SHA256 = "0" * 64


class AccessPolicyError(ValueError):
    """Base class for fixed-code access-policy failures."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PolicyLoadError(AccessPolicyError):
    pass


class SigningKeyError(AccessPolicyError):
    pass


class GrantValidationError(AccessPolicyError):
    pass


class AuditLogError(AccessPolicyError):
    pass


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RolePolicy:
    methods: tuple[str, ...]
    tools: tuple[str, ...]
    resources: tuple[str, ...]
    max_calls: int

    def __post_init__(self) -> None:
        try:
            methods = _scope_list(self.methods, "policy_methods_invalid")
            tools = _scope_list(self.tools, "policy_tools_invalid")
            resources = _scope_list(self.resources, "policy_resources_invalid")
        except GrantValidationError as exc:
            raise PolicyLoadError(exc.code) from exc
        if not _is_int(self.max_calls) or not 1 <= self.max_calls <= MAX_CALLS:
            raise PolicyLoadError("policy_max_calls_invalid")
        object.__setattr__(self, "methods", methods)
        object.__setattr__(self, "tools", tools)
        object.__setattr__(self, "resources", resources)


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    issuer: str
    audience: str
    max_ttl_seconds: int
    roles: Mapping[str, RolePolicy]
    source_sha256: str
    schema: str = POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != POLICY_SCHEMA:
            raise PolicyLoadError("policy_schema_invalid")
        _policy_text(self.issuer, "policy_issuer_invalid")
        _policy_text(self.audience, "policy_audience_invalid")
        if not _is_int(self.max_ttl_seconds) or not 1 <= self.max_ttl_seconds <= MAX_GRANT_TTL_SECONDS:
            raise PolicyLoadError("policy_max_ttl_invalid")
        if not isinstance(self.roles, Mapping) or not 1 <= len(self.roles) <= MAX_ROLES:
            raise PolicyLoadError("policy_roles_invalid")
        roles = dict(self.roles)
        if any(not isinstance(name, str) or not _ROLE_NAME_RE.fullmatch(name) for name in roles):
            raise PolicyLoadError("policy_role_name_invalid")
        if any(not isinstance(role, RolePolicy) for role in roles.values()):
            raise PolicyLoadError("policy_role_invalid")
        if not isinstance(self.source_sha256, str) or not _HEX_64_RE.fullmatch(self.source_sha256):
            raise PolicyLoadError("policy_digest_invalid")
        object.__setattr__(self, "roles", MappingProxyType(roles))


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason: str
    token_ref: str
    decision_ref: str
    grant_ref: str = ""
    subject_ref: str = ""
    role_refs: tuple[str, ...] = ()
    method_ref: str = ""
    target_ref: str = ""
    app_id_ref: str = ""
    session_ref: str = ""
    purpose_ref: str = ""
    transaction_ref: str = ""
    calls_used: int | None = None
    max_calls: int | None = None
    visible_tool_count: int | None = None
    filtered_tool_count: int | None = None
    schema: str = DECISION_SCHEMA
    raw_free: bool = True
    raw_returned: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "role_refs", tuple(self.role_refs))
        if self.schema != DECISION_SCHEMA or self.raw_free is not True or self.raw_returned is not False:
            raise ValueError("Access decisions must use the raw-free decision schema.")
        if not isinstance(self.allowed, bool) or self.reason not in _DECISION_REASONS:
            raise ValueError("Access decision outcome is invalid.")
        if not _valid_ref(self.token_ref) or not _valid_ref(self.decision_ref):
            raise ValueError("Access decision primary references are invalid.")
        optional_refs = (
            self.grant_ref,
            self.subject_ref,
            self.method_ref,
            self.target_ref,
            self.app_id_ref,
            self.session_ref,
            self.purpose_ref,
            self.transaction_ref,
        )
        if any(value and not _valid_ref(value) for value in optional_refs):
            raise ValueError("Access decision reference is invalid.")
        if any(not _valid_ref(value) for value in self.role_refs):
            raise ValueError("Access decision role reference is invalid.")
        for value in (self.calls_used, self.max_calls, self.visible_tool_count, self.filtered_tool_count):
            if value is not None and (not _is_int(value) or value < 0):
                raise ValueError("Access decision count is invalid.")

    @property
    def action(self) -> str:
        return "allow" if self.allowed else "deny"

    @property
    def authorized(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": self.schema,
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "token_ref": self.token_ref,
            "decision_ref": self.decision_ref,
            "ref_scheme": REF_SCHEME,
            "raw_free": True,
            "raw_returned": False,
        }
        for key in (
            "grant_ref",
            "subject_ref",
            "method_ref",
            "target_ref",
            "app_id_ref",
            "session_ref",
            "purpose_ref",
            "transaction_ref",
        ):
            item = getattr(self, key)
            if item:
                value[key] = item
        if self.role_refs:
            value["role_refs"] = list(self.role_refs)
        for key in ("calls_used", "max_calls", "visible_tool_count", "filtered_tool_count"):
            item = getattr(self, key)
            if item is not None:
                value[key] = item
        return value

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class _GrantContext:
    grant_ref: str
    subject_ref: str
    role_refs: tuple[str, ...]
    purpose_ref: str
    app_id_ref: str
    session_ref: str
    methods: tuple[str, ...]
    tools: tuple[str, ...]
    resources: tuple[str, ...]
    max_calls: int
    expires_at: int


@dataclass(slots=True)
class _GrantUsage:
    calls: int
    expires_at: int


def load_policy(path: str | Path, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> AccessPolicy:
    """Load the strict v1 access policy from a bounded, regular, non-symlink file."""

    if not _is_int(max_bytes) or not 1 <= max_bytes <= HARD_MAX_POLICY_BYTES:
        raise PolicyLoadError("policy_size_bound_invalid")
    candidate = _coerce_path(path, "policy_path_invalid", PolicyLoadError)
    content = _read_policy_file(candidate, max_bytes)
    try:
        text = content.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise PolicyLoadError("policy_duplicate_json_key") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise PolicyLoadError("policy_json_invalid") from exc
    return _policy_from_mapping(value, hashlib.sha256(content).hexdigest())


load_access_policy = load_policy


def mint_grant(
    policy: AccessPolicy,
    signing_key: str | bytes | bytearray | memoryview,
    *,
    subject: str,
    roles: str | Sequence[str],
    purpose: str,
    app_id: str,
    session_id: str,
    methods: Sequence[str],
    tools: Sequence[str],
    resources: Sequence[str],
    ttl_seconds: int,
    max_calls: int,
    not_before_seconds: int = 0,
    now: int | None = None,
    jti: str | None = None,
) -> str:
    """Mint a narrowly scoped HS256 grant after checking it against the role envelope."""

    if not isinstance(policy, AccessPolicy):
        raise GrantValidationError("policy_required")
    key = _normalize_key(signing_key, "signing_key")
    subject_value = _identity_text(subject, "subject_invalid")
    purpose_value = _identity_text(purpose, "purpose_invalid")
    app_value = _identity_text(app_id, "app_id_invalid")
    session_value = _identity_text(session_id, "session_id_invalid")
    role_values = _grant_roles(roles)
    method_values = _scope_list(methods, "methods_claim_invalid")
    tool_values = _scope_list(tools, "tools_claim_invalid")
    resource_values = _scope_list(resources, "resources_claim_invalid")
    role_methods, role_tools, role_resources, role_max_calls = _role_envelope(policy, role_values)
    _require_scope_subset(method_values, role_methods)
    _require_scope_subset(tool_values, role_tools)
    _require_scope_subset(resource_values, role_resources)
    if not _is_int(ttl_seconds) or not 1 <= ttl_seconds <= policy.max_ttl_seconds:
        raise GrantValidationError("grant_ttl_invalid")
    if not _is_int(not_before_seconds) or not 0 <= not_before_seconds < ttl_seconds:
        raise GrantValidationError("grant_nbf_invalid")
    if not _is_int(max_calls) or not 1 <= max_calls <= role_max_calls:
        raise GrantValidationError("grant_max_calls_invalid")
    issued_at = int(time.time()) if now is None else now
    if not _is_int(issued_at) or issued_at < 0:
        raise GrantValidationError("grant_iat_invalid")
    grant_id = _identity_text(jti or secrets.token_urlsafe(24), "jti_invalid")
    payload = {
        "iss": policy.issuer,
        "aud": policy.audience,
        "sub": subject_value,
        "jti": grant_id,
        "iat": issued_at,
        "nbf": issued_at + not_before_seconds,
        "exp": issued_at + ttl_seconds,
        "roles": list(role_values),
        "purpose": purpose_value,
        "app_id": app_value,
        "session_id": session_value,
        "methods": list(method_values),
        "tools": list(tool_values),
        "resources": list(resource_values),
        "max_calls": max_calls,
    }
    token = jwt.encode(payload, key, algorithm="HS256", headers={"typ": "JWT"})
    if not isinstance(token, str) or len(token.encode("ascii", errors="ignore")) > MAX_TOKEN_BYTES:
        raise GrantValidationError("minted_grant_invalid")
    return token


class ChainedAuditLog:
    """Append-only, hash- and HMAC-chained JSONL decisions."""

    def __init__(self, path: str | Path, hmac_key: str | bytes | bytearray | memoryview) -> None:
        self._path = _coerce_path(path, "audit_path_invalid", AuditLogError)
        self._key = _derive_key(_normalize_key(hmac_key, "audit_key"), b"audit-chain")
        self._lock = threading.Lock()
        self._sequence, self._last_sha256, self._size = _inspect_audit_file(self._path, self._key, missing_ok=True)

    @property
    def entry_count(self) -> int:
        with self._lock:
            return self._sequence

    @property
    def last_sha256(self) -> str:
        with self._lock:
            return self._last_sha256

    def append_decision(self, decision: AccessDecision, *, recorded_at: int | None = None) -> str:
        if not isinstance(decision, AccessDecision) or decision.raw_returned is not False:
            raise AuditLogError("audit_decision_invalid")
        timestamp = int(time.time()) if recorded_at is None else recorded_at
        if not _is_int(timestamp) or timestamp < 0:
            raise AuditLogError("audit_timestamp_invalid")
        with self._lock:
            self._refresh_if_changed()
            payload = {
                "schema": AUDIT_SCHEMA,
                "sequence": self._sequence + 1,
                "recorded_at": timestamp,
                "previous_sha256": self._last_sha256,
                "decision": decision.to_dict(),
            }
            canonical = _canonical_json(payload)
            entry_sha256 = hashlib.sha256(canonical).hexdigest()
            chain_hmac = _audit_hmac(self._key, entry_sha256, self._last_sha256)
            record = {
                **payload,
                "entry_sha256": entry_sha256,
                "chain_hmac_sha256": chain_hmac,
            }
            line = _canonical_json(record) + b"\n"
            if len(line) > MAX_AUDIT_LINE_BYTES or self._size + len(line) > MAX_AUDIT_BYTES:
                raise AuditLogError("audit_size_limit_exceeded")
            _append_regular_file(self._path, line)
            self._sequence += 1
            self._last_sha256 = entry_sha256
            self._size += len(line)
            return entry_sha256

    def verify(self) -> bool:
        with self._lock:
            try:
                _inspect_audit_file(self._path, self._key, missing_ok=False)
            except AuditLogError:
                return False
            return True

    def _refresh_if_changed(self) -> None:
        if _path_has_symlink(self._path):
            raise AuditLogError("audit_symlink_disallowed")
        try:
            size = self._path.stat().st_size if self._path.exists() else 0
        except OSError as exc:
            raise AuditLogError("audit_path_invalid") from exc
        if size == self._size:
            return
        self._sequence, self._last_sha256, self._size = _inspect_audit_file(
            self._path,
            self._key,
            missing_ok=True,
        )


def verify_audit_log(path: str | Path, hmac_key: str | bytes | bytearray | memoryview) -> bool:
    try:
        candidate = _coerce_path(path, "audit_path_invalid", AuditLogError)
        key = _derive_key(_normalize_key(hmac_key, "audit_key"), b"audit-chain")
        _inspect_audit_file(candidate, key, missing_ok=False)
    except AccessPolicyError:
        return False
    return True


class AccessPolicyController:
    """Session-bound, fail-closed authorization for isolated agent grants."""

    def __init__(
        self,
        policy: AccessPolicy,
        signing_key: str | bytes | bytearray | memoryview,
        *,
        app_id: str,
        session_id: str,
        purpose: str | None = None,
        audit_path: str | Path | None = None,
        audit_key: str | bytes | bytearray | memoryview | None = None,
    ) -> None:
        if not isinstance(policy, AccessPolicy):
            raise PolicyLoadError("policy_required")
        self.policy = policy
        self._signing_key = _normalize_key(signing_key, "signing_key")
        self._ref_key = _derive_key(self._signing_key, b"decision-refs")
        self._app_id = _identity_text(app_id, "app_id_invalid")
        self._session_id = _identity_text(session_id, "session_id_invalid")
        self._purpose = None if purpose is None else _identity_text(purpose, "purpose_invalid")
        self._app_id_ref = self._ref("app-id", self._app_id)
        self._session_ref = self._ref("session", self._session_id)
        self._purpose_ref = self._ref("purpose", self._purpose) if self._purpose is not None else ""
        self._policy_ref = self._ref("policy", self.policy.source_sha256)
        self._issuer_ref = self._ref("issuer", self.policy.issuer)
        self._audience_ref = self._ref("audience", self.policy.audience)
        self._lock = threading.Lock()
        self._usage: dict[str, _GrantUsage] = {}
        self._decision_counts: Counter[str] = Counter()
        self._reason_counts: Counter[str] = Counter()
        self._audit_error_count = 0
        if audit_path is None:
            if audit_key is not None:
                raise AuditLogError("audit_key_without_path")
            self._audit: ChainedAuditLog | None = None
        else:
            self._audit = ChainedAuditLog(audit_path, audit_key if audit_key is not None else self._signing_key)
            self._audit_path_ref = self._ref("audit-path", str(Path(audit_path).absolute()))

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        signing_key: str | bytes | bytearray | memoryview,
        *,
        app_id: str,
        session_id: str,
        purpose: str | None = None,
        audit_path: str | Path | None = None,
        audit_key: str | bytes | bytearray | memoryview | None = None,
        max_policy_bytes: int = DEFAULT_MAX_POLICY_BYTES,
    ) -> AccessPolicyController:
        return cls(
            load_policy(path, max_bytes=max_policy_bytes),
            signing_key,
            app_id=app_id,
            session_id=session_id,
            purpose=purpose,
            audit_path=audit_path,
            audit_key=audit_key,
        )

    def mint_grant(
        self,
        *,
        subject: str,
        roles: str | Sequence[str],
        purpose: str | None = None,
        methods: Sequence[str],
        tools: Sequence[str],
        resources: Sequence[str],
        ttl_seconds: int,
        max_calls: int,
        not_before_seconds: int = 0,
        now: int | None = None,
        jti: str | None = None,
    ) -> str:
        purpose_value = self._purpose if purpose is None else _identity_text(purpose, "purpose_invalid")
        if purpose_value is None:
            raise GrantValidationError("purpose_required")
        if self._purpose is not None and not hmac.compare_digest(
            self._ref("purpose", purpose_value),
            self._purpose_ref,
        ):
            raise GrantValidationError("purpose_mismatch")
        return mint_grant(
            self.policy,
            self._signing_key,
            subject=subject,
            roles=roles,
            purpose=purpose_value,
            app_id=self._app_id,
            session_id=self._session_id,
            methods=methods,
            tools=tools,
            resources=resources,
            ttl_seconds=ttl_seconds,
            max_calls=max_calls,
            not_before_seconds=not_before_seconds,
            now=now,
            jti=jti,
        )

    def authorize(self, token: str, message: object) -> AccessDecision:
        return self.authorize_client_message(token, message)

    def authenticate_grant(self, token: str) -> AccessDecision:
        token_ref = self._ref("token", token if isinstance(token, str) else type(token).__name__)
        try:
            grant = self._validate_grant(token)
        except GrantValidationError as exc:
            return self._finish_decision(self._decision(False, exc.code, token_ref=token_ref))
        return self._finish_decision(
            self._decision_from_grant(True, "authenticated", token_ref, grant)
        )

    def authorize_client_message(
        self,
        token: str,
        message: object,
        *,
        transaction_ref: str = "",
    ) -> AccessDecision:
        token_ref = self._ref("token", token if isinstance(token, str) else type(token).__name__)
        method = message.get("method") if isinstance(message, Mapping) else None
        method_ref = self._ref("method", method) if isinstance(method, str) else ""
        bound = {"transaction_ref": transaction_ref} if transaction_ref else {}
        try:
            grant = self._validate_grant(token)
        except GrantValidationError as exc:
            return self._finish_decision(
                self._decision(False, exc.code, token_ref=token_ref, method_ref=method_ref, **bound)
            )
        if not _valid_client_message(message):
            return self._finish_decision(
                self._decision_from_grant(
                    False, "jsonrpc_message_invalid", token_ref, grant, method_ref=method_ref, **bound
                )
            )
        assert isinstance(method, str)
        if not _matches_scope(method, grant.methods):
            return self._finish_decision(
                self._decision_from_grant(False, "method_denied", token_ref, grant, method_ref=method_ref, **bound)
            )

        target_ref = ""
        params = message.get("params")
        if method == "tools/call":
            if not isinstance(params, Mapping) or not _runtime_value(params.get("name")):
                return self._finish_decision(
                    self._decision_from_grant(
                        False,
                        "tool_call_invalid",
                        token_ref,
                        grant,
                        method_ref=method_ref,
                        **bound,
                    )
                )
            tool_name = str(params["name"])
            target_ref = self._ref("tool", tool_name)
            if not _matches_scope(tool_name, grant.tools):
                return self._finish_decision(
                    self._decision_from_grant(
                        False,
                        "tool_denied",
                        token_ref,
                        grant,
                        method_ref=method_ref,
                        target_ref=target_ref,
                        **bound,
                    )
                )
        elif method == "resources/read":
            if not isinstance(params, Mapping) or not _runtime_value(params.get("uri")):
                return self._finish_decision(
                    self._decision_from_grant(
                        False,
                        "resource_read_invalid",
                        token_ref,
                        grant,
                        method_ref=method_ref,
                        **bound,
                    )
                )
            resource_uri = str(params["uri"])
            target_ref = self._ref("resource", resource_uri)
            if not _matches_scope(resource_uri, grant.resources):
                return self._finish_decision(
                    self._decision_from_grant(
                        False,
                        "resource_denied",
                        token_ref,
                        grant,
                        method_ref=method_ref,
                        target_ref=target_ref,
                        **bound,
                    )
                )

        calls_used = self._consume_call(grant)
        if calls_used is None:
            return self._finish_decision(
                self._decision_from_grant(
                    False,
                    "call_budget_exhausted",
                    token_ref,
                    grant,
                    method_ref=method_ref,
                    target_ref=target_ref,
                    calls_used=grant.max_calls,
                    **bound,
                )
            )
        return self._finish_decision(
            self._decision_from_grant(
                True,
                "authorized",
                token_ref,
                grant,
                method_ref=method_ref,
                target_ref=target_ref,
                calls_used=calls_used,
                **bound,
            )
        )

    def filter_tools_list(self, token: str, response: object) -> dict[str, Any]:
        return self.filter_tools_list_response(token, response)

    def filter_tools_list_response(self, token: str, response: object) -> dict[str, Any]:
        token_ref = self._ref("token", token if isinstance(token, str) else type(token).__name__)
        method_ref = self._ref("method", "tools/list")
        try:
            grant = self._validate_grant(token)
        except GrantValidationError as exc:
            self._finish_decision(self._decision(False, exc.code, token_ref=token_ref, method_ref=method_ref))
            return _empty_tools_response(response)
        if not _matches_scope("tools/list", grant.methods):
            self._finish_decision(
                self._decision_from_grant(False, "method_denied", token_ref, grant, method_ref=method_ref)
            )
            return _empty_tools_response(response)
        copied = _copy_tools_response(response)
        result = copied.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            self._finish_decision(
                self._decision_from_grant(False, "tool_list_response_invalid", token_ref, grant, method_ref=method_ref)
            )
            return _empty_tools_response(response)
        original_tools = result["tools"]
        visible = [
            dict(tool)
            for tool in original_tools
            if isinstance(tool, Mapping)
            and _runtime_value(tool.get("name"))
            and _matches_scope(str(tool["name"]), grant.tools)
        ]
        result["tools"] = visible
        decision = self._finish_decision(
            self._decision_from_grant(
                True,
                "tool_list_filtered",
                token_ref,
                grant,
                method_ref=method_ref,
                visible_tool_count=len(visible),
                filtered_tool_count=len(original_tools) - len(visible),
            )
        )
        return copied if decision.allowed else _empty_tools_response(response)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            self._prune_usage_locked(int(time.time()))
            decision_counts = dict(sorted(self._decision_counts.items()))
            reason_counts = dict(sorted(self._reason_counts.items()))
            active_grants = len(self._usage)
            consumed_calls = sum(item.calls for item in self._usage.values())
            audit_error_count = self._audit_error_count
        audit_summary: dict[str, Any] = {
            "enabled": self._audit is not None,
            "error_count": audit_error_count,
            "raw_free": True,
            "raw_returned": False,
        }
        if self._audit is not None:
            audit_summary.update(
                {
                    "path_ref": self._audit_path_ref,
                    "entry_count": self._audit.entry_count,
                    "last_entry_sha256": self._audit.last_sha256,
                }
            )
        value: dict[str, Any] = {
            "schema": CONTROLLER_SUMMARY_SCHEMA,
            "complete": audit_error_count == 0,
            "default_action": "deny",
            "policy_ref": self._policy_ref,
            "issuer_ref": self._issuer_ref,
            "audience_ref": self._audience_ref,
            "app_id_ref": self._app_id_ref,
            "session_ref": self._session_ref,
            "role_count": len(self.policy.roles),
            "active_grant_count": active_grants,
            "active_grant_calls_consumed": consumed_calls,
            "decision_counts": decision_counts,
            "reason_counts": reason_counts,
            "audit": audit_summary,
            "ref_scheme": REF_SCHEME,
            "raw_free": True,
            "raw_returned": False,
        }
        if self._purpose_ref:
            value["purpose_ref"] = self._purpose_ref
        value["summary_ref"] = self._ref("summary", _canonical_json(value))
        return value

    controller_summary = summary
    raw_free_summary = summary

    def _validate_grant(self, token: object) -> _GrantContext:
        if not isinstance(token, str) or not token:
            raise GrantValidationError("grant_invalid")
        try:
            encoded_token = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise GrantValidationError("grant_invalid") from exc
        if len(encoded_token) > MAX_TOKEN_BYTES:
            raise GrantValidationError("grant_invalid")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise GrantValidationError("grant_invalid") from exc
        if header.get("alg") != "HS256" or "crit" in header or "jku" in header or "x5u" in header:
            raise GrantValidationError("grant_algorithm_invalid")
        try:
            claims = jwt.decode(
                token,
                self._signing_key,
                algorithms=["HS256"],
                issuer=self.policy.issuer,
                audience=self.policy.audience,
                leeway=0,
                options={"require": sorted(_REQUIRED_GRANT_CLAIMS), "strict_aud": True},
            )
        except jwt.ExpiredSignatureError as exc:
            raise GrantValidationError("grant_expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise GrantValidationError("grant_not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise GrantValidationError("grant_issuer_mismatch") from exc
        except jwt.InvalidAudienceError as exc:
            raise GrantValidationError("grant_audience_mismatch") from exc
        except jwt.InvalidSignatureError as exc:
            raise GrantValidationError("grant_signature_invalid") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise GrantValidationError("grant_claims_invalid") from exc
        except jwt.InvalidTokenError as exc:
            raise GrantValidationError("grant_invalid") from exc
        except (TypeError, ValueError, OverflowError) as exc:
            raise GrantValidationError("grant_invalid") from exc
        if not isinstance(claims, dict) or set(claims) != _REQUIRED_GRANT_CLAIMS:
            raise GrantValidationError("grant_claims_invalid")
        for key in ("iat", "nbf", "exp"):
            if not _is_int(claims.get(key)):
                raise GrantValidationError("grant_time_claims_invalid")
        issued_at = claims["iat"]
        not_before = claims["nbf"]
        expires_at = claims["exp"]
        if not issued_at <= not_before < expires_at:
            raise GrantValidationError("grant_time_claims_invalid")
        if expires_at - issued_at > self.policy.max_ttl_seconds:
            raise GrantValidationError("grant_ttl_exceeded")
        subject = _identity_text(claims.get("sub"), "subject_invalid")
        grant_id = _identity_text(claims.get("jti"), "jti_invalid")
        purpose = _identity_text(claims.get("purpose"), "purpose_invalid")
        app_id = _identity_text(claims.get("app_id"), "app_id_invalid")
        session_id = _identity_text(claims.get("session_id"), "session_id_invalid")
        app_id_ref = self._ref("app-id", app_id)
        session_ref = self._ref("session", session_id)
        purpose_ref = self._ref("purpose", purpose)
        if not hmac.compare_digest(app_id_ref, self._app_id_ref):
            raise GrantValidationError("grant_app_id_mismatch")
        if not hmac.compare_digest(session_ref, self._session_ref):
            raise GrantValidationError("grant_session_mismatch")
        if self._purpose_ref and not hmac.compare_digest(purpose_ref, self._purpose_ref):
            raise GrantValidationError("grant_purpose_mismatch")
        role_values = _grant_roles(claims.get("roles"))
        methods = _scope_list(claims.get("methods"), "methods_claim_invalid")
        tools = _scope_list(claims.get("tools"), "tools_claim_invalid")
        resources = _scope_list(claims.get("resources"), "resources_claim_invalid")
        role_methods, role_tools, role_resources, role_max_calls = _role_envelope(self.policy, role_values)
        _require_scope_subset(methods, role_methods)
        _require_scope_subset(tools, role_tools)
        _require_scope_subset(resources, role_resources)
        max_calls = claims.get("max_calls")
        if not _is_int(max_calls) or not 1 <= max_calls <= role_max_calls:
            raise GrantValidationError("grant_max_calls_invalid")
        return _GrantContext(
            grant_ref=self._ref("grant", grant_id),
            subject_ref=self._ref("subject", subject),
            role_refs=tuple(sorted(self._ref("role", role) for role in role_values)),
            purpose_ref=purpose_ref,
            app_id_ref=app_id_ref,
            session_ref=session_ref,
            methods=methods,
            tools=tools,
            resources=resources,
            max_calls=max_calls,
            expires_at=expires_at,
        )

    def _consume_call(self, grant: _GrantContext) -> int | None:
        now = int(time.time())
        with self._lock:
            self._prune_usage_locked(now)
            usage = self._usage.get(grant.grant_ref)
            if usage is None:
                usage = _GrantUsage(calls=0, expires_at=grant.expires_at)
                self._usage[grant.grant_ref] = usage
            else:
                usage.expires_at = min(usage.expires_at, grant.expires_at)
            if usage.calls >= grant.max_calls:
                return None
            usage.calls += 1
            return usage.calls

    def _prune_usage_locked(self, now: int) -> None:
        expired = [grant_ref for grant_ref, usage in self._usage.items() if usage.expires_at <= now]
        for grant_ref in expired:
            self._usage.pop(grant_ref, None)

    def _decision_from_grant(
        self,
        allowed: bool,
        reason: str,
        token_ref: str,
        grant: _GrantContext,
        **extra: Any,
    ) -> AccessDecision:
        return self._decision(
            allowed,
            reason,
            token_ref=token_ref,
            grant_ref=grant.grant_ref,
            subject_ref=grant.subject_ref,
            role_refs=grant.role_refs,
            app_id_ref=grant.app_id_ref,
            session_ref=grant.session_ref,
            purpose_ref=grant.purpose_ref,
            max_calls=grant.max_calls,
            **extra,
        )

    def _decision(self, allowed: bool, reason: str, *, token_ref: str, **fields: Any) -> AccessDecision:
        base = {
            "allowed": bool(allowed),
            "reason": reason,
            "token_ref": token_ref,
            **{key: value for key, value in fields.items() if value not in (None, "", ())},
        }
        decision_ref = self._ref("decision", _canonical_json(base))
        return AccessDecision(
            allowed=bool(allowed),
            reason=reason,
            token_ref=token_ref,
            decision_ref=decision_ref,
            **fields,
        )

    def _finish_decision(self, decision: AccessDecision) -> AccessDecision:
        if self._audit is not None:
            try:
                self._audit.append_decision(decision)
            except AuditLogError:
                with self._lock:
                    self._audit_error_count += 1
                if decision.allowed:
                    decision = self._decision(
                        False,
                        "audit_write_failed",
                        token_ref=decision.token_ref,
                        grant_ref=decision.grant_ref,
                        subject_ref=decision.subject_ref,
                        role_refs=decision.role_refs,
                        method_ref=decision.method_ref,
                        target_ref=decision.target_ref,
                        app_id_ref=decision.app_id_ref,
                        session_ref=decision.session_ref,
                        purpose_ref=decision.purpose_ref,
                        transaction_ref=decision.transaction_ref,
                        calls_used=decision.calls_used,
                        max_calls=decision.max_calls,
                    )
        with self._lock:
            self._decision_counts[decision.action] += 1
            self._reason_counts[decision.reason] += 1
        return decision

    def _ref(self, kind: str, value: object) -> str:
        if isinstance(value, bytes):
            encoded = value
        else:
            encoded = str(value).encode("utf-8", errors="surrogatepass")
        message = kind.encode("ascii") + b"\0" + encoded
        return hmac.new(self._ref_key, message, hashlib.sha256).hexdigest()


def authorize_client_message(
    controller: AccessPolicyController,
    token: str,
    message: object,
    *,
    transaction_ref: str = "",
) -> AccessDecision:
    if not isinstance(controller, AccessPolicyController):
        raise TypeError("controller must be an AccessPolicyController")
    return controller.authorize_client_message(token, message, transaction_ref=transaction_ref)


def filter_tools_list_response(
    controller: AccessPolicyController,
    token: str,
    response: object,
) -> dict[str, Any]:
    if not isinstance(controller, AccessPolicyController):
        raise TypeError("controller must be an AccessPolicyController")
    return controller.filter_tools_list_response(token, response)


def _policy_from_mapping(value: object, source_sha256: str) -> AccessPolicy:
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL_KEYS:
        raise PolicyLoadError("policy_schema_invalid")
    if value.get("schema") != POLICY_SCHEMA:
        raise PolicyLoadError("policy_schema_invalid")
    issuer = _policy_text(value.get("issuer"), "policy_issuer_invalid")
    audience = _policy_text(value.get("audience"), "policy_audience_invalid")
    max_ttl = value.get("max_ttl_seconds")
    if not _is_int(max_ttl) or not 1 <= max_ttl <= MAX_GRANT_TTL_SECONDS:
        raise PolicyLoadError("policy_max_ttl_invalid")
    raw_roles = value.get("roles")
    if not isinstance(raw_roles, dict) or not 1 <= len(raw_roles) <= MAX_ROLES:
        raise PolicyLoadError("policy_roles_invalid")
    roles: dict[str, RolePolicy] = {}
    for name, role_value in raw_roles.items():
        if not isinstance(name, str) or not _ROLE_NAME_RE.fullmatch(name):
            raise PolicyLoadError("policy_role_name_invalid")
        if not isinstance(role_value, dict) or set(role_value) != _ROLE_KEYS:
            raise PolicyLoadError("policy_role_invalid")
        try:
            methods = _scope_list(role_value.get("methods"), "policy_methods_invalid")
            tools = _scope_list(role_value.get("tools"), "policy_tools_invalid")
            resources = _scope_list(role_value.get("resources"), "policy_resources_invalid")
        except GrantValidationError as exc:
            raise PolicyLoadError(exc.code) from exc
        max_calls = role_value.get("max_calls")
        if not _is_int(max_calls) or not 1 <= max_calls <= MAX_CALLS:
            raise PolicyLoadError("policy_max_calls_invalid")
        roles[name] = RolePolicy(methods=methods, tools=tools, resources=resources, max_calls=max_calls)
    return AccessPolicy(
        issuer=issuer,
        audience=audience,
        max_ttl_seconds=max_ttl,
        roles=roles,
        source_sha256=source_sha256,
    )


def _role_envelope(
    policy: AccessPolicy,
    roles: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], int]:
    selected: list[RolePolicy] = []
    for role in roles:
        role_policy = policy.roles.get(role)
        if role_policy is None:
            raise GrantValidationError("grant_role_unknown")
        selected.append(role_policy)
    return (
        tuple(sorted({item for role in selected for item in role.methods})),
        tuple(sorted({item for role in selected for item in role.tools})),
        tuple(sorted({item for role in selected for item in role.resources})),
        max(role.max_calls for role in selected),
    )


def _grant_roles(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        items: object = [value]
    else:
        items = value
    if not isinstance(items, (list, tuple)) or not 1 <= len(items) <= MAX_GRANT_ROLES:
        raise GrantValidationError("grant_roles_invalid")
    result: list[str] = []
    for item in items:
        if not isinstance(item, str) or not _ROLE_NAME_RE.fullmatch(item):
            raise GrantValidationError("grant_roles_invalid")
        if item in result:
            raise GrantValidationError("grant_roles_invalid")
        result.append(item)
    return tuple(result)


def _scope_list(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_SCOPE_ITEMS:
        raise GrantValidationError(code)
    result: list[str] = []
    for item in value:
        if not _valid_scope_pattern(item) or item in result:
            raise GrantValidationError(code)
        result.append(item)
    return tuple(result)


def _valid_scope_pattern(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    encoded = value.encode("utf-8", errors="surrogatepass")
    if len(encoded) > MAX_SCOPE_VALUE_BYTES or any(
        ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
    ):
        return False
    if "*" not in value:
        return True
    return value not in {"*", "/*"} and value.endswith("/*") and value.count("*") == 1


def _require_scope_subset(requested: tuple[str, ...], allowed: tuple[str, ...]) -> None:
    if any(not any(_pattern_is_subset(item, parent) for parent in allowed) for item in requested):
        raise GrantValidationError("grant_scope_escalation")


def _pattern_is_subset(candidate: str, allowed: str) -> bool:
    if candidate == allowed:
        return True
    if not allowed.endswith("/*"):
        return False
    allowed_prefix = allowed[:-1]
    if candidate.endswith("/*"):
        return candidate[:-1].startswith(allowed_prefix)
    return candidate.startswith(allowed_prefix)


def _matches_scope(value: str, patterns: tuple[str, ...]) -> bool:
    return any(value == pattern or (pattern.endswith("/*") and value.startswith(pattern[:-1])) for pattern in patterns)


def _valid_client_message(value: object) -> bool:
    if not isinstance(value, Mapping) or value.get("jsonrpc") != "2.0":
        return False
    method = value.get("method")
    return _runtime_value(method)


def _runtime_value(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    encoded = value.encode("utf-8", errors="surrogatepass")
    return len(encoded) <= MAX_SCOPE_VALUE_BYTES and not any(
        ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
    )


def _copy_tools_response(response: object) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        return {"jsonrpc": "2.0", "id": None, "result": {"tools": []}}
    copied = dict(response)
    result = response.get("result")
    if isinstance(result, Mapping):
        copied["result"] = dict(result)
    return copied


def _empty_tools_response(response: object) -> dict[str, Any]:
    copied = _copy_tools_response(response)
    result = copied.get("result")
    if isinstance(result, dict):
        result["tools"] = []
    elif "error" not in copied:
        copied["result"] = {"tools": []}
    return copied


def _identity_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GrantValidationError(code)
    encoded = value.encode("utf-8", errors="surrogatepass")
    if len(encoded) > MAX_IDENTITY_VALUE_BYTES or any(
        ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
    ):
        raise GrantValidationError(code)
    return value


def _policy_text(value: object, code: str) -> str:
    try:
        return _identity_text(value, code)
    except GrantValidationError as exc:
        raise PolicyLoadError(code) from exc


def _normalize_key(value: object, label: str) -> bytes:
    if isinstance(value, str):
        key = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        key = bytes(value)
    else:
        raise SigningKeyError(f"{label}_missing")
    if not MIN_SIGNING_KEY_BYTES <= len(key) <= MAX_SIGNING_KEY_BYTES:
        raise SigningKeyError(f"{label}_weak")
    return key


def _derive_key(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, b"k-guard-access-policy\0" + label, hashlib.sha256).digest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AuditLogError("canonical_json_invalid") from exc


def _audit_hmac(key: bytes, entry_sha256: str, previous_sha256: str) -> str:
    message = b"k-guard-audit-entry-v1\0" + previous_sha256.encode("ascii") + b"\0" + entry_sha256.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _inspect_audit_file(path: Path, key: bytes, *, missing_ok: bool) -> tuple[int, str, int]:
    if _path_has_symlink(path):
        raise AuditLogError("audit_symlink_disallowed")
    try:
        if not path.exists():
            if missing_ok:
                parent = path.parent
                if not parent.exists() or not parent.is_dir() or _path_has_symlink(parent):
                    raise AuditLogError("audit_parent_invalid")
                return 0, _INITIAL_AUDIT_SHA256, 0
            raise AuditLogError("audit_path_not_found")
        if not path.is_file():
            raise AuditLogError("audit_path_invalid")
        size = path.stat().st_size
        if size > MAX_AUDIT_BYTES:
            raise AuditLogError("audit_size_limit_exceeded")
        content = path.read_bytes()
    except AuditLogError:
        raise
    except OSError as exc:
        raise AuditLogError("audit_read_failed") from exc
    if len(content) != size:
        raise AuditLogError("audit_changed_during_read")
    if not content:
        return 0, _INITIAL_AUDIT_SHA256, 0
    if not content.endswith(b"\n"):
        raise AuditLogError("audit_truncated")
    previous = _INITIAL_AUDIT_SHA256
    sequence = 0
    for raw_line in content.splitlines():
        if not raw_line or len(raw_line) + 1 > MAX_AUDIT_LINE_BYTES:
            raise AuditLogError("audit_line_invalid")
        try:
            record = json.loads(
                raw_line.decode("ascii"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (_DuplicateJsonKey, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise AuditLogError("audit_json_invalid") from exc
        if not isinstance(record, dict) or set(record) != _AUDIT_RECORD_KEYS:
            raise AuditLogError("audit_record_invalid")
        decision = record.get("decision")
        if not _valid_decision_payload(decision):
            raise AuditLogError("audit_decision_invalid")
        if record.get("schema") != AUDIT_SCHEMA or record.get("sequence") != sequence + 1:
            raise AuditLogError("audit_sequence_invalid")
        if not _is_int(record.get("recorded_at")) or record["recorded_at"] < 0:
            raise AuditLogError("audit_timestamp_invalid")
        if record.get("previous_sha256") != previous:
            raise AuditLogError("audit_chain_invalid")
        entry_sha256 = record.get("entry_sha256")
        chain_hmac = record.get("chain_hmac_sha256")
        if not isinstance(entry_sha256, str) or not _HEX_64_RE.fullmatch(entry_sha256):
            raise AuditLogError("audit_digest_invalid")
        if not isinstance(chain_hmac, str) or not _HEX_64_RE.fullmatch(chain_hmac):
            raise AuditLogError("audit_hmac_invalid")
        payload = {
            key_name: record[key_name]
            for key_name in record
            if key_name not in {"entry_sha256", "chain_hmac_sha256"}
        }
        actual_sha256 = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if not hmac.compare_digest(actual_sha256, entry_sha256):
            raise AuditLogError("audit_digest_mismatch")
        actual_hmac = _audit_hmac(key, entry_sha256, previous)
        if not hmac.compare_digest(actual_hmac, chain_hmac):
            raise AuditLogError("audit_hmac_mismatch")
        previous = entry_sha256
        sequence += 1
    return sequence, previous, len(content)


def _append_regular_file(path: Path, content: bytes) -> None:
    if _path_has_symlink(path):
        raise AuditLogError("audit_symlink_disallowed")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise AuditLogError("audit_path_invalid")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short audit write")
            view = view[written:]
        os.fsync(descriptor)
    except AuditLogError:
        raise
    except OSError as exc:
        raise AuditLogError("audit_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_policy_file(path: Path, max_bytes: int) -> bytes:
    if _path_has_symlink(path):
        raise PolicyLoadError("policy_symlink_disallowed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise PolicyLoadError("policy_path_not_file")
        if not 1 <= file_stat.st_size <= max_bytes:
            raise PolicyLoadError("policy_size_invalid")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if not 1 <= len(content) <= max_bytes:
            raise PolicyLoadError("policy_size_invalid")
        if os.fstat(descriptor).st_size != file_stat.st_size or len(content) != file_stat.st_size:
            raise PolicyLoadError("policy_changed_during_read")
        return content
    except PolicyLoadError:
        raise
    except OSError as exc:
        raise PolicyLoadError("policy_read_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _coerce_path(
    value: object,
    code: str,
    error_type: type[AccessPolicyError] = AccessPolicyError,
) -> Path:
    try:
        text = os.fspath(value)
    except (TypeError, ValueError) as exc:
        raise error_type(code) from exc
    if not isinstance(text, (str, bytes)) or not text or "\x00" in os.fsdecode(text):
        raise error_type(code)
    try:
        return Path(os.fsdecode(text))
    except (TypeError, ValueError, OSError) as exc:
        raise error_type(code) from exc


def _path_has_symlink(path: Path) -> bool:
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            if current.is_symlink():
                return True
    except (OSError, RuntimeError, ValueError):
        return True
    return False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-finite JSON constant")


def _valid_decision_payload(value: object) -> bool:
    required = {
        "schema",
        "allowed",
        "action",
        "reason",
        "token_ref",
        "decision_ref",
        "ref_scheme",
        "raw_free",
        "raw_returned",
    }
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(_DECISION_KEYS):
        return False
    allowed = value.get("allowed")
    if (
        not isinstance(allowed, bool)
        or value.get("action") != ("allow" if allowed else "deny")
        or value.get("reason") not in _DECISION_REASONS
        or value.get("schema") != DECISION_SCHEMA
        or value.get("ref_scheme") != REF_SCHEME
        or value.get("raw_free") is not True
        or value.get("raw_returned") is not False
    ):
        return False
    if not _valid_ref(value.get("token_ref")) or not _valid_ref(value.get("decision_ref")):
        return False
    optional_refs = {
        "grant_ref",
        "subject_ref",
        "method_ref",
        "target_ref",
        "app_id_ref",
        "session_ref",
        "purpose_ref",
        "transaction_ref",
    }
    if any(key in value and not _valid_ref(value[key]) for key in optional_refs):
        return False
    role_refs = value.get("role_refs", [])
    if not isinstance(role_refs, list) or any(not _valid_ref(item) for item in role_refs):
        return False
    for key in ("calls_used", "max_calls", "visible_tool_count", "filtered_tool_count"):
        if key in value and (not _is_int(value[key]) or value[key] < 0):
            return False
    return True


def _valid_ref(value: object) -> bool:
    return isinstance(value, str) and _HEX_64_RE.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
