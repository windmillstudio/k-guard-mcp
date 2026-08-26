from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from k_guard_mcp.access_policy import AccessPolicyController, verify_audit_log
from k_guard_mcp.database_gate import (
    DatabaseGateError,
    DbPrincipal,
    QueryBudget,
    RbacGate,
    SqlAstGate,
    SqliteReadOnlySession,
    TableGrant,
    ValidatedReadQuery,
)
from k_guard_mcp.provenance import evidence_bundle, object_artifact


CONTROL_VALIDATION_SCHEMA = "k_guard_control_validation.v1"
CONTROL_TOOLCHAIN_SCHEMA = "k_guard_control_validation_toolchain.v1"


def control_validation_toolchain_contract() -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    paths = (
        package_root / "access_policy.py",
        package_root / "database_gate.py",
        package_root / "mcp_http_proxy.py",
        package_root / "mcp_proxy.py",
        package_root / "control_validation.py",
    )
    digest = hashlib.sha256()
    hashed = 0
    for path in paths:
        try:
            relative = path.relative_to(package_root).as_posix().encode("ascii")
            content = path.read_bytes()
        except (OSError, ValueError, UnicodeEncodeError):
            continue
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        hashed += 1
    return {
        "schema": CONTROL_TOOLCHAIN_SCHEMA,
        "sha256": digest.hexdigest(),
        "expected_file_count": len(paths),
        "hashed_file_count": hashed,
        "complete": hashed == len(paths),
        "raw_returned": False,
    }


def run_control_validation() -> dict[str, Any]:
    toolchain = control_validation_toolchain_contract()
    runs = [_run_once(), _run_once()]
    projections = [_run_projection(run) for run in runs]
    repeat_exact = projections[0] == projections[1]
    cases = runs[0]["cases"]
    passed = (
        toolchain["complete"] is True
        and repeat_exact
        and bool(cases)
        and all(case.get("passed") is True for case in cases)
        and all(run.get("complete") is True for run in runs)
    )
    report: dict[str, Any] = {
        "schema": CONTROL_VALIDATION_SCHEMA,
        "complete": passed,
        "passed": passed,
        "profile": "synthetic_fail_closed_control_validation",
        "toolchain_contract": toolchain,
        "repeat": {
            "run_count": len(runs),
            "exact": repeat_exact,
            "projection_sha256": hashlib.sha256(_canonical_json(projections[0]).encode("ascii")).hexdigest(),
        },
        "case_count": len(cases),
        "passed_case_count": sum(case.get("passed") is True for case in cases),
        "domains": {
            "agent_jit_jea": _domain_summary(cases, "agent_jit_jea"),
            "database_ast_rbac_isolation": _domain_summary(cases, "database_ast_rbac_isolation"),
        },
        "cases": cases,
        "claim_boundary": {
            "synthetic_control_regression_only": True,
            "live_application_authorization_proved": False,
            "production_database_policy_proved": False,
        },
        "raw_free": True,
    }
    report["evidence_bundle"] = evidence_bundle(
        subject="control-validation",
        producer="k_guard_mcp.control_validation",
        artifacts=[object_artifact("control-validation-report", report, role="validation")],
    )
    return report


def _run_once() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    control_errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="k-guard-control-validation-") as directory:
        root = Path(directory)
        try:
            cases.extend(_access_cases(root))
        except Exception as exc:
            control_errors.append(f"access:{type(exc).__name__}")
        try:
            cases.extend(_database_cases(root))
        except Exception as exc:
            control_errors.append(f"database:{type(exc).__name__}")
    expected_names = {
        "access_valid_grant_allowed",
        "access_unauthorized_tool_denied",
        "access_resource_scope_denied",
        "access_call_budget_enforced",
        "access_tampered_grant_denied",
        "access_expired_grant_denied",
        "access_tool_inventory_filtered",
        "access_audit_chain_verified",
        "database_bounded_select_allowed",
        "database_mutation_denied_by_ast",
        "database_join_and_star_denied",
        "database_column_rbac_denied",
        "database_wrong_role_denied",
        "database_explain_and_read_succeeded",
        "database_forged_write_blocked",
        "database_result_budget_enforced",
        "database_path_escape_denied",
        "database_content_unchanged",
    }
    observed_names = {str(case.get("name")) for case in cases}
    if observed_names != expected_names:
        control_errors.append("case_inventory_mismatch")
    cases.sort(key=lambda item: str(item["name"]))
    return {
        "complete": not control_errors and all(case.get("passed") is True for case in cases),
        "control_errors": control_errors,
        "cases": cases,
        "raw_free": True,
    }


def _access_cases(root: Path) -> list[dict[str, Any]]:
    policy_path = root / "access-policy.json"
    audit_path = root / "access-audit.jsonl"
    policy_path.write_text(
        json.dumps(
            {
                "schema": "k_guard_agent_access_policy.v1",
                "issuer": "https://validation.example.invalid/k-guard",
                "audience": "k-guard-control-validation",
                "max_ttl_seconds": 120,
                "roles": {
                    "reviewer": {
                        "methods": ["tools/list", "tools/call", "resources/read"],
                        "tools": ["check_my_app", "repo/read/*"],
                        "resources": ["k-guard://public/*"],
                        "max_calls": 20,
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
        app_id="validation-app",
        session_id="validation-session",
        purpose="control-validation",
        audit_path=audit_path,
        audit_key=key,
    )
    token = controller.mint_grant(
        subject="validation-agent",
        roles=["reviewer"],
        methods=["tools/list", "tools/call", "resources/read"],
        tools=["check_my_app", "repo/read/*"],
        resources=["k-guard://public/*"],
        ttl_seconds=60,
        max_calls=10,
    )
    valid = controller.authorize_client_message(token, _tool_call("check_my_app"))
    denied_tool = controller.authorize_client_message(token, _tool_call("admin/delete"))
    denied_resource = controller.authorize_client_message(
        token,
        {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "k-guard://private/keys"}},
    )

    budget_token = controller.mint_grant(
        subject="budget-agent",
        roles=["reviewer"],
        methods=["tools/call"],
        tools=["check_my_app"],
        resources=[],
        ttl_seconds=60,
        max_calls=1,
    )
    first_budget = controller.authorize_client_message(budget_token, _tool_call("check_my_app", identifier=4))
    second_budget = controller.authorize_client_message(budget_token, _tool_call("check_my_app", identifier=5))

    middle = len(token) // 2
    replacement = "A" if token[middle] != "A" else "B"
    tampered = token[:middle] + replacement + token[middle + 1 :]
    tampered_decision = controller.authenticate_grant(tampered)

    expired = controller.mint_grant(
        subject="expired-agent",
        roles=["reviewer"],
        methods=["tools/call"],
        tools=["check_my_app"],
        resources=[],
        ttl_seconds=1,
        max_calls=1,
        now=int(time.time()) - 10,
    )
    expired_decision = controller.authenticate_grant(expired)

    filtered = controller.filter_tools_list_response(
        token,
        {
            "jsonrpc": "2.0",
            "id": 6,
            "result": {"tools": [{"name": "check_my_app"}, {"name": "admin/delete"}]},
        },
    )
    visible_tools = filtered.get("result", {}).get("tools", [])
    summary = controller.controller_summary()
    return [
        _case("access_valid_grant_allowed", "agent_jit_jea", valid.allowed is True, valid.reason),
        _case("access_unauthorized_tool_denied", "agent_jit_jea", denied_tool.allowed is False and denied_tool.reason == "tool_denied", denied_tool.reason),
        _case("access_resource_scope_denied", "agent_jit_jea", denied_resource.allowed is False and denied_resource.reason == "resource_denied", denied_resource.reason),
        _case("access_call_budget_enforced", "agent_jit_jea", first_budget.allowed is True and second_budget.reason == "call_budget_exhausted", second_budget.reason),
        _case("access_tampered_grant_denied", "agent_jit_jea", tampered_decision.allowed is False and tampered_decision.reason in {"grant_signature_invalid", "grant_invalid"}, tampered_decision.reason),
        _case("access_expired_grant_denied", "agent_jit_jea", expired_decision.allowed is False and expired_decision.reason == "grant_expired", expired_decision.reason),
        _case("access_tool_inventory_filtered", "agent_jit_jea", len(visible_tools) == 1 and visible_tools[0].get("name") == "check_my_app", len(visible_tools)),
        _case("access_audit_chain_verified", "agent_jit_jea", verify_audit_log(audit_path, key) and summary.get("audit", {}).get("error_count") == 0, summary.get("audit", {}).get("entry_count", 0)),
    ]


def _database_cases(root: Path) -> list[dict[str, Any]]:
    database = root / "validation.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, secret TEXT)")
        connection.executemany(
            "INSERT INTO users(id, email, secret) VALUES (?, ?, ?)",
            [(1, "one@example.invalid", "marker-one"), (2, "two@example.invalid", "x" * 4096)],
        )
        connection.commit()
    finally:
        connection.close()
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    budget = QueryBudget(max_rows=10, max_result_bytes=64 * 1024, max_cell_bytes=8 * 1024)
    grant = TableGrant(
        role="reviewer",
        database="app",
        schema="main",
        table="users",
        columns=frozenset({"id", "email"}),
        budget=budget,
    )
    principal = DbPrincipal("validation-subject-ref", frozenset({"reviewer"}))
    ast = SqlAstGate()
    allowed = ast.validate("SELECT id, email FROM users WHERE id > 0 LIMIT 2", budget=budget)
    mutation = ast.validate("DELETE FROM users", budget=budget)
    join = ast.validate("SELECT users.id FROM users JOIN admins ON admins.id = users.id LIMIT 2", budget=budget)
    star = ast.validate("SELECT * FROM users LIMIT 2", budget=budget)
    secret_query = ast.validate("SELECT id, secret FROM users LIMIT 2", budget=budget)
    assert allowed.query is not None and secret_query.query is not None
    column_denied = RbacGate().authorize(secret_query.query, principal, grant, database="app")
    role_denied = RbacGate().authorize(
        allowed.query,
        DbPrincipal("other-subject-ref", frozenset({"other"})),
        grant,
        database="app",
    )
    allowed_rbac = RbacGate().authorize(allowed.query, principal, grant, database="app")
    explain_ok = False
    read_count = 0
    with SqliteReadOnlySession(database, root=root, grant=grant) as session:
        plan = session.explain(allowed.query)
        rows = session.execute_read(allowed.query)
        explain_ok = plan.get("plan_row_count", 0) > 0 and plan.get("raw_free") is True
        read_count = len(rows)

    forged = ValidatedReadQuery(
        query_ref="forged",
        ast_sha256="0" * 64,
        dialect="sqlite",
        schema="main",
        table="users",
        columns=("id",),
        limit=1,
        _sql="DELETE FROM users",
    )
    forged_denied = _raises_code(
        lambda: _execute_forged(database, root, grant, forged),
        "sqlite_read_denied_or_failed",
    )

    tight_grant = TableGrant(
        role="reviewer",
        database="app",
        schema="main",
        table="users",
        columns=frozenset({"id", "secret"}),
        budget=QueryBudget(max_rows=10, max_result_bytes=1024, max_cell_bytes=512),
    )
    tight_query = ast.validate("SELECT id, secret FROM users LIMIT 2", budget=tight_grant.budget)
    assert tight_query.query is not None
    result_budget_denied = _raises_code(
        lambda: _execute_read(database, root, tight_grant, tight_query.query),
        {"sqlite_cell_budget_exceeded", "sqlite_result_budget_exceeded", "sqlite_read_denied_or_failed"},
    )

    with tempfile.TemporaryDirectory(prefix="k-guard-outside-database-") as outside_directory:
        outside = Path(outside_directory) / "outside.sqlite"
        outside.write_bytes(database.read_bytes())
        path_escape_denied = _raises_code(
            lambda: SqliteReadOnlySession(outside, root=root, grant=grant),
            "sqlite_path_outside_root_or_invalid",
        )
    after = hashlib.sha256(database.read_bytes()).hexdigest()
    return [
        _case("database_bounded_select_allowed", "database_ast_rbac_isolation", allowed.allowed and allowed_rbac.allowed, allowed_rbac.code),
        _case("database_mutation_denied_by_ast", "database_ast_rbac_isolation", mutation.code == "sql_operation_not_select", mutation.code),
        _case("database_join_and_star_denied", "database_ast_rbac_isolation", join.allowed is False and star.allowed is False, f"{join.code}:{star.code}"),
        _case("database_column_rbac_denied", "database_ast_rbac_isolation", column_denied.code == "rbac_column_denied", column_denied.code),
        _case("database_wrong_role_denied", "database_ast_rbac_isolation", role_denied.code == "rbac_role_denied", role_denied.code),
        _case("database_explain_and_read_succeeded", "database_ast_rbac_isolation", explain_ok and read_count == 2, read_count),
        _case("database_forged_write_blocked", "database_ast_rbac_isolation", forged_denied, "sqlite_authorizer"),
        _case("database_result_budget_enforced", "database_ast_rbac_isolation", result_budget_denied, "bounded_result"),
        _case("database_path_escape_denied", "database_ast_rbac_isolation", path_escape_denied, "contained_path"),
        _case("database_content_unchanged", "database_ast_rbac_isolation", before == after, before == after),
    ]


def _execute_forged(path: Path, root: Path, grant: TableGrant, query: ValidatedReadQuery) -> None:
    with SqliteReadOnlySession(path, root=root, grant=grant) as session:
        session.execute_read(query)


def _execute_read(path: Path, root: Path, grant: TableGrant, query: ValidatedReadQuery) -> None:
    with SqliteReadOnlySession(path, root=root, grant=grant) as session:
        session.execute_read(query)


def _raises_code(operation: Callable[[], Any], expected: str | set[str]) -> bool:
    expected_codes = {expected} if isinstance(expected, str) else set(expected)
    try:
        operation()
    except DatabaseGateError as exc:
        return exc.code in expected_codes
    return False


def _tool_call(name: str, *, identifier: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {"name": name, "arguments": {}}}


def _case(name: str, domain: str, passed: bool, observed: Any) -> dict[str, Any]:
    safe_observed = observed if isinstance(observed, (str, int, float, bool)) or observed is None else type(observed).__name__
    return {
        "name": name,
        "domain": domain,
        "passed": bool(passed),
        "observed": safe_observed,
        "raw_returned": False,
    }


def _domain_summary(cases: list[dict[str, Any]], domain: str) -> dict[str, Any]:
    selected = [case for case in cases if case.get("domain") == domain]
    return {
        "passed": bool(selected) and all(case.get("passed") is True for case in selected),
        "case_count": len(selected),
        "failed_case_count": sum(case.get("passed") is not True for case in selected),
        "raw_returned": False,
    }


def _run_projection(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "complete": run.get("complete"),
        "control_errors": list(run.get("control_errors", [])),
        "cases": [
            {
                "name": case.get("name"),
                "domain": case.get("domain"),
                "passed": case.get("passed"),
                "observed": case.get("observed"),
            }
            for case in run.get("cases", [])
            if isinstance(case, dict)
        ],
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "CONTROL_TOOLCHAIN_SCHEMA",
    "CONTROL_VALIDATION_SCHEMA",
    "control_validation_toolchain_contract",
    "run_control_validation",
]
