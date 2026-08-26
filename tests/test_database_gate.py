from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from k_guard_mcp.database_gate import (
    DatabaseGateError,
    DbPrincipal,
    QueryBudget,
    RbacGate,
    SqlAstGate,
    SqliteReadOnlySession,
    TableGrant,
    ValidatedReadQuery,
    build_database_gate_report,
)
from k_guard_mcp.scanner import KGuardScanner


def _grant(**budget_overrides: object) -> TableGrant:
    return TableGrant(
        role="support-readonly",
        database="app",
        schema="main",
        table="users",
        columns=frozenset({"id", "email"}),
        budget=QueryBudget(**budget_overrides),
    )


def _database(path: Path, *, large_value: str = "") -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, secret TEXT)")
        connection.executemany(
            "INSERT INTO users(id, email, secret) VALUES (?, ?, ?)",
            [(1, "one@example.test", large_value or "s1"), (2, "two@example.test", "s2")],
        )
        connection.commit()
    finally:
        connection.close()


def test_ast_gate_allows_only_one_bounded_explicit_select() -> None:
    decision = SqlAstGate().validate(
        "SELECT id, email FROM main.users WHERE id = 1 LIMIT 5",
        budget=QueryBudget(max_rows=10),
    )

    assert decision.allowed is True
    assert decision.query is not None
    assert decision.query.table == "users"
    assert decision.query.columns == ("email", "id")
    assert decision.query.limit == 5
    assert decision.query._sql.startswith("SELECT")


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("DELETE FROM users", "sql_operation_not_select"),
        ("UPDATE users SET email = 'x'", "sql_operation_not_select"),
        ("SELECT id FROM users; SELECT email FROM users", "sql_statement_count_invalid"),
        ("SELECT * FROM users LIMIT 1", "sql_star_disallowed"),
        ("SELECT lower(email) FROM users LIMIT 1", "sql_func_disallowed"),
        ("WITH x AS (SELECT id FROM users) SELECT id FROM x LIMIT 1", "sql_cte_disallowed"),
        ("SELECT u.id FROM users u JOIN admins a ON a.id = u.id LIMIT 1", "sql_join_disallowed"),
        ("SELECT id FROM users UNION SELECT id FROM admins LIMIT 2", "sql_operation_not_select"),
        ("SELECT id FROM users", "sql_literal_limit_required"),
        ("SELECT id FROM users LIMIT 101", "sql_row_limit_exceeded"),
        ("SELECT id FROM temp.users LIMIT 1", "sql_system_schema_denied"),
    ],
)
def test_ast_gate_rejects_mutation_and_complex_query_shapes(sql: str, code: str) -> None:
    decision = SqlAstGate().validate(sql, budget=QueryBudget(max_rows=100))
    assert decision.allowed is False
    assert decision.code == code


def test_rbac_denies_wrong_role_database_table_and_column() -> None:
    query = SqlAstGate().validate("SELECT id, email FROM users LIMIT 2").query
    assert query is not None
    grant = _grant()
    allowed = RbacGate().authorize(
        query,
        DbPrincipal("subject-ref", frozenset({"support-readonly"})),
        grant,
        database="app",
    )
    assert allowed.allowed is True

    wrong_role = RbacGate().authorize(
        query,
        DbPrincipal("subject-ref", frozenset({"developer"})),
        grant,
        database="app",
    )
    assert wrong_role.code == "rbac_role_denied"
    wrong_database = RbacGate().authorize(
        query,
        DbPrincipal("subject-ref", frozenset({"support-readonly"})),
        grant,
        database="other",
    )
    assert wrong_database.code == "rbac_database_denied"

    column_query = SqlAstGate().validate("SELECT id, secret FROM users LIMIT 2").query
    assert column_query is not None
    wrong_column = RbacGate().authorize(
        column_query,
        DbPrincipal("subject-ref", frozenset({"support-readonly"})),
        grant,
        database="app",
    )
    assert wrong_column.code == "rbac_column_denied"


def test_sqlite_read_runs_after_ast_rbac_and_explain_without_changing_file(tmp_path: Path) -> None:
    database = tmp_path / "app.sqlite"
    _database(database)
    grant = _grant()
    query = SqlAstGate().validate("SELECT id, email FROM users WHERE id > 0 LIMIT 2", budget=grant.budget).query
    assert query is not None
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    with SqliteReadOnlySession(database, root=tmp_path, grant=grant) as session:
        plan = session.explain(query)
        rows = session.execute_read(query)

    assert len(rows) == 2
    assert plan["schema"] == "k_guard_sqlite_explain.v1"
    assert plan["plan_row_count"] > 0
    assert plan["raw_free"] is True
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert "one@example.test" not in json.dumps(plan)


def test_sqlite_wal_snapshot_reads_uncheckpointed_rows_without_touching_source(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.sqlite"
    writer = sqlite3.connect(database)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, secret TEXT)"
        )
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute(
            "INSERT INTO users(id, email, secret) VALUES (?, ?, ?)",
            (1, "wal@example.test", "s1"),
        )
        writer.commit()
        source_members = sorted(tmp_path.glob("app.sqlite*"))
        assert {path.name for path in source_members} == {
            "app.sqlite",
            "app.sqlite-shm",
            "app.sqlite-wal",
        }
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_members
        }
        grant = _grant()
        query = SqlAstGate().validate(
            "SELECT id, email FROM users LIMIT 2",
            budget=grant.budget,
        ).query
        assert query is not None

        with SqliteReadOnlySession(database, root=tmp_path, grant=grant) as session:
            rows = session.execute_read(query)

        after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(tmp_path.glob("app.sqlite*"))
        }
        assert rows == [(1, "wal@example.test")]
        assert after == before
        assert not list(tmp_path.glob("k-guard-sqlite-snapshot-*"))
    finally:
        writer.close()


def test_sqlite_session_fails_closed_when_source_sidecar_changes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.sqlite"
    _database(database)
    sidecar = tmp_path / "app.sqlite-shm"
    sidecar.write_bytes(b"before")
    grant = _grant()
    query = SqlAstGate().validate(
        "SELECT id, email FROM users LIMIT 2",
        budget=grant.budget,
    ).query
    assert query is not None

    with pytest.raises(DatabaseGateError, match="sqlite_source_changed_during_read"):
        with SqliteReadOnlySession(database, root=tmp_path, grant=grant) as session:
            assert len(session.execute_read(query)) == 2
            sidecar.write_bytes(b"after")


def test_forged_validated_query_is_still_denied_by_sqlite_backstops(tmp_path: Path) -> None:
    database = tmp_path / "app.sqlite"
    _database(database)
    grant = _grant()
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

    with SqliteReadOnlySession(database, root=tmp_path, grant=grant) as session:
        with pytest.raises(DatabaseGateError, match="sqlite_read_denied_or_failed"):
            session.execute_read(forged)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM users").fetchone()[0] == 2
    finally:
        connection.close()


def test_sqlite_path_size_and_symlink_boundaries_fail_closed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.sqlite"
    _database(outside)
    try:
        with pytest.raises(DatabaseGateError, match="outside_root"):
            SqliteReadOnlySession(outside, root=tmp_path, grant=_grant())

        oversized = tmp_path / "oversized.sqlite"
        _database(oversized, large_value="x" * 4096)
        with pytest.raises(DatabaseGateError, match="size_invalid"):
            SqliteReadOnlySession(oversized, root=tmp_path, grant=_grant(max_database_bytes=1024))

        link = tmp_path / "linked.sqlite"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            return
        with pytest.raises(DatabaseGateError, match="symlink_disallowed"):
            SqliteReadOnlySession(link, root=tmp_path, grant=_grant())
    finally:
        outside.unlink(missing_ok=True)


def test_result_cell_budget_aborts_without_returning_partial_rows(tmp_path: Path) -> None:
    database = tmp_path / "app.sqlite"
    _database(database, large_value="x" * 4096)
    grant = TableGrant(
        role="support-readonly",
        database="app",
        schema="main",
        table="users",
        columns=frozenset({"id", "secret"}),
        budget=QueryBudget(max_cell_bytes=512, max_result_bytes=1024),
    )
    query = SqlAstGate().validate("SELECT id, secret FROM users LIMIT 2", budget=grant.budget).query
    assert query is not None

    with SqliteReadOnlySession(database, root=tmp_path, grant=grant) as session:
        with pytest.raises(DatabaseGateError):
            session.execute_read(query)


def test_database_gate_report_is_raw_free_and_signed() -> None:
    report = build_database_gate_report(
        "SELECT id, email FROM users LIMIT 2",
        dialect="sqlite",
        principal=DbPrincipal("subject-ref", frozenset({"support-readonly"})),
        grant=_grant(),
        database="app",
    )
    rendered = json.dumps(report, ensure_ascii=False)

    assert report["passed"] is True
    assert report["raw_free"] is True
    assert report["evidence_bundle"]["schema"] == "k_guard_evidence_bundle.v1"
    assert "SELECT id" not in rendered
    assert "support-readonly" not in rendered
    assert "users" not in rendered


def test_corrupt_database_marks_workspace_connector_coverage_incomplete(tmp_path: Path) -> None:
    (tmp_path / "broken.sqlite").write_bytes(b"not-a-database")

    result = KGuardScanner().scan_workspace(tmp_path, include_flow=False)
    rules = {finding.rule_id for finding in result.findings}

    assert "CONNECTOR_LOCAL_STORAGE_COVERAGE_INCOMPLETE" in rules
    assert result.metadata["connector_coverage"]["complete"] is False
    assert result.metadata["review_coverage"]["domains"]["data_management"]["status"] == "incomplete_fail_closed"


def test_valid_database_records_ast_rbac_explain_and_isolation_coverage(tmp_path: Path) -> None:
    database = tmp_path / "app.sqlite"
    _database(database)

    result = KGuardScanner().scan_workspace(tmp_path, include_flow=False)
    evidence = result.metadata["connector_coverage"]

    assert evidence["complete"] is True
    assert evidence["database_count"] == 1
    assert evidence["sampled_table_count"] == 1
    assert "sql_ast_single_bounded_select" in evidence["database_controls"]
    assert "mode_ro_query_only_authorizer" in evidence["database_controls"]
    assert "detached_source_snapshot_with_wal_sidecars" in evidence["database_controls"]
    assert "source_sidecar_before_after_hash" in evidence["database_controls"]


def test_linked_database_is_not_opened_and_fails_coverage(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-linked-target.sqlite"
    _database(outside)
    link = tmp_path / "linked.sqlite"
    try:
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation is unavailable")
        result = KGuardScanner().scan_workspace(tmp_path, include_flow=False)
        assert result.metadata["connector_coverage"]["complete"] is False
        assert any(
            finding.rule_id == "CONNECTOR_LOCAL_STORAGE_COVERAGE_INCOMPLETE"
            and "sqlite_symlink_disallowed" in finding.evidence
            for finding in result.findings
        )
    finally:
        outside.unlink(missing_ok=True)
