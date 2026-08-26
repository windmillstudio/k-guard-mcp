from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import quote

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.provenance import evidence_bundle, object_artifact


DATABASE_GATE_SCHEMA = "k_guard_database_gate.v1"
DATABASE_VALIDATION_SCHEMA = "k_guard_database_validation.v1"
MAX_SQL_BYTES = 64 * 1024
SYSTEM_SCHEMAS = frozenset({"information_schema", "mysql", "performance_schema", "pg_catalog", "sys", "temp"})
SQLITE_SOURCE_MEMBER_SUFFIXES = ("", "-wal", "-shm", "-journal")
SQLITE_SNAPSHOT_COPY_SUFFIXES = ("", "-wal", "-journal")


class DatabaseGateError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class QueryBudget:
    max_rows: int = 100
    max_result_bytes: int = 1024 * 1024
    max_cell_bytes: int = 64 * 1024
    max_database_bytes: int = 64 * 1024 * 1024
    max_plan_rows: int = 128
    max_vm_steps: int = 100_000
    timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        for name in (
            "max_rows",
            "max_result_bytes",
            "max_cell_bytes",
            "max_database_bytes",
            "max_plan_rows",
            "max_vm_steps",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")


@dataclass(frozen=True, slots=True)
class DbPrincipal:
    subject_ref: str
    roles: frozenset[str]

    def __post_init__(self) -> None:
        if not self.subject_ref or any(character in self.subject_ref for character in "\r\n\x00"):
            raise ValueError("subject_ref is invalid")
        normalized = frozenset(_identifier(item, "role") for item in self.roles)
        if not normalized:
            raise ValueError("at least one role is required")
        object.__setattr__(self, "roles", normalized)


@dataclass(frozen=True, slots=True)
class TableGrant:
    role: str
    database: str
    schema: str
    table: str
    columns: frozenset[str]
    budget: QueryBudget = field(default_factory=QueryBudget)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _identifier(self.role, "role"))
        object.__setattr__(self, "database", _identifier(self.database, "database"))
        object.__setattr__(self, "schema", _identifier(self.schema, "schema"))
        object.__setattr__(self, "table", _identifier(self.table, "table"))
        columns = frozenset(_identifier(item, "column") for item in self.columns)
        if not columns:
            raise ValueError("columns must not be empty")
        object.__setattr__(self, "columns", columns)


@dataclass(frozen=True, slots=True)
class ValidatedReadQuery:
    query_ref: str
    ast_sha256: str
    dialect: str
    schema: str
    table: str
    columns: tuple[str, ...]
    limit: int
    _sql: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class QueryDecision:
    allowed: bool
    code: str
    query: ValidatedReadQuery | None
    checks: tuple[dict[str, Any], ...]

    def to_report(self, *, policy_ref: str = "") -> dict[str, Any]:
        query = self.query
        payload: dict[str, Any] = {
            "schema": DATABASE_GATE_SCHEMA,
            "passed": self.allowed,
            "decision": "allow" if self.allowed else "deny",
            "code": self.code,
            "policy_ref": policy_ref,
            "query_ref": query.query_ref if query else "",
            "ast_sha256": query.ast_sha256 if query else "",
            "resource_refs": {
                "schema": evidence_hash(query.schema) if query else "",
                "table": evidence_hash(query.table) if query else "",
                "columns": [evidence_hash(item) for item in query.columns] if query else [],
            },
            "row_limit": query.limit if query else 0,
            "checks": list(self.checks),
            "hash_scheme": evidence_hash_scheme(),
            "raw_free": True,
        }
        payload["evidence_bundle"] = evidence_bundle(
            subject="database-policy-decision",
            producer="k_guard_mcp.database_gate",
            artifacts=[object_artifact("database-decision", payload, role="gate")],
        )
        return payload


class SqlAstGate:
    """Accept only a deliberately small, bounded, single-table SELECT shape."""

    def validate(self, sql: str, *, dialect: str = "sqlite", budget: QueryBudget | None = None) -> QueryDecision:
        checks: list[dict[str, Any]] = []
        active_budget = budget or QueryBudget()
        if not isinstance(sql, str) or not sql.strip() or "\x00" in sql:
            return _deny("sql_invalid", checks)
        if len(sql.encode("utf-8", errors="ignore")) > MAX_SQL_BYTES:
            return _deny("sql_size_limit_exceeded", checks)
        try:
            statements = sqlglot.parse(sql, read=dialect, error_level="RAISE")
        except (ParseError, TokenError, ValueError):
            return _deny("sql_parse_failed", checks)
        if len(statements) != 1:
            return _deny("sql_statement_count_invalid", checks)
        statement = statements[0]
        if not isinstance(statement, exp.Select):
            return _deny("sql_operation_not_select", checks)
        checks.append(_check("single_select", True, statement.key))

        prohibited = (
            exp.CTE,
            exp.Subquery,
            exp.Join,
            exp.Union,
            exp.Intersect,
            exp.Except,
            exp.Func,
            exp.Star,
        )
        for node_type in prohibited:
            if statement.find(node_type) is not None:
                return _deny(f"sql_{node_type.__name__.lower()}_disallowed", checks)
        checks.append(_check("restricted_ast_shape", True, "simple-select"))

        tables = list(statement.find_all(exp.Table))
        if len(tables) != 1:
            return _deny("sql_table_count_invalid", checks)
        table_node = tables[0]
        schema = _identifier(table_node.db or "main", "schema")
        table = _identifier(table_node.name, "table")
        if schema in SYSTEM_SCHEMAS:
            return _deny("sql_system_schema_denied", checks)

        columns = tuple(sorted({_identifier(node.name, "column") for node in statement.find_all(exp.Column)}))
        if not columns:
            return _deny("sql_explicit_columns_required", checks)
        checks.append(_check("explicit_columns", True, len(columns)))

        limit_node = statement.find(exp.Limit)
        if limit_node is None or not isinstance(limit_node.expression, exp.Literal) or not limit_node.expression.is_int:
            return _deny("sql_literal_limit_required", checks)
        try:
            limit = int(limit_node.expression.this)
        except (TypeError, ValueError):
            return _deny("sql_literal_limit_required", checks)
        if limit <= 0 or limit > active_budget.max_rows:
            return _deny("sql_row_limit_exceeded", checks)
        checks.append(_check("bounded_limit", True, limit))

        try:
            normalized = statement.sql(dialect=dialect, normalize=True, pretty=False)
        except Exception:
            return _deny("sql_ast_serialization_failed", checks)
        query = ValidatedReadQuery(
            query_ref=evidence_hash(sql),
            ast_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            dialect=dialect,
            schema=schema,
            table=table,
            columns=columns,
            limit=limit,
            _sql=sql,
        )
        return QueryDecision(True, "allowed", query, tuple(checks))


class RbacGate:
    def authorize(
        self,
        query: ValidatedReadQuery,
        principal: DbPrincipal,
        grant: TableGrant,
        *,
        database: str,
    ) -> QueryDecision:
        checks: list[dict[str, Any]] = []
        if grant.role not in principal.roles:
            return _deny("rbac_role_denied", checks, query)
        checks.append(_check("role", True, evidence_hash(grant.role)))
        if _identifier(database, "database") != grant.database:
            return _deny("rbac_database_denied", checks, query)
        if query.schema != grant.schema or query.table != grant.table:
            return _deny("rbac_table_denied", checks, query)
        checks.append(_check("resource", True, evidence_hash(f"{query.schema}.{query.table}")))
        denied_columns = set(query.columns) - set(grant.columns)
        if denied_columns:
            return _deny("rbac_column_denied", checks, query)
        checks.append(_check("columns", True, len(query.columns)))
        if query.limit > grant.budget.max_rows:
            return _deny("rbac_row_budget_denied", checks, query)
        checks.append(_check("row_budget", True, query.limit))
        return QueryDecision(True, "allowed", query, tuple(checks))


class SqliteReadOnlySession:
    """A closed read surface: callers receive bounded rows, never a connection."""

    def __init__(self, path: str | Path, *, root: str | Path, grant: TableGrant) -> None:
        self.path = _contained_database(path, root, grant.budget)
        self.root = Path(root).resolve(strict=True)
        self.grant = grant
        self._connection: sqlite3.Connection | None = None
        self._deadline = 0.0
        self._steps = 0
        self._phase = "closed"
        self._observed_reads: set[tuple[str, str]] = set()
        self._catalog_table = ""
        self._lock = threading.RLock()
        self._source_manifest: tuple[tuple[str, int, str], ...] | None = None
        self._snapshot_directory: tempfile.TemporaryDirectory[str] | None = None
        self._snapshot_path: Path | None = None

    def __enter__(self) -> "SqliteReadOnlySession":
        connection: sqlite3.Connection | None = None
        try:
            (
                self._snapshot_directory,
                self._snapshot_path,
                self._source_manifest,
            ) = _create_sqlite_snapshot(
                self.path,
                root=self.root,
                budget=self.grant.budget,
            )
            encoded = quote(self._snapshot_path.as_posix(), safe="/:@")
            uri = f"file:{encoded}?mode=ro&cache=private"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=min(self.grant.budget.timeout_seconds, 5.0),
                cached_statements=0,
                check_same_thread=True,
            )
            connection.enable_load_extension(False)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA cell_size_check=ON")
            connection.execute("PRAGMA mmap_size=0")
            _apply_sqlite_limits(connection, self.grant.budget)
            connection.set_progress_handler(self._progress, 100)
            connection.set_authorizer(self._authorize)
        except DatabaseGateError:
            try:
                if connection is not None:
                    connection.close()
            finally:
                self._cleanup_snapshot()
            raise
        except Exception as exc:
            try:
                if connection is not None:
                    connection.close()
            finally:
                self._cleanup_snapshot()
            raise DatabaseGateError("sqlite_open_or_hardening_failed") from exc
        self._connection = connection
        self._phase = "ready"
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        connection = self._connection
        self._connection = None
        self._phase = "closed"
        source_changed = False
        close_failed = False
        try:
            if connection is not None:
                connection.close()
        except Exception:
            close_failed = True
        try:
            if self._source_manifest is None:
                source_changed = True
            else:
                source_changed = (
                    _sqlite_source_manifest(self.path, self.grant.budget)
                    != self._source_manifest
                )
        except DatabaseGateError:
            source_changed = True
        cleanup_failed = False
        try:
            self._cleanup_snapshot()
        except Exception:
            cleanup_failed = True
        if source_changed:
            raise DatabaseGateError("sqlite_source_changed_during_read")
        if close_failed:
            raise DatabaseGateError("sqlite_close_failed")
        if cleanup_failed:
            raise DatabaseGateError("sqlite_snapshot_cleanup_failed")

    def _cleanup_snapshot(self) -> None:
        snapshot_directory = self._snapshot_directory
        self._snapshot_directory = None
        self._snapshot_path = None
        self._source_manifest = None
        if snapshot_directory is not None:
            snapshot_directory.cleanup()

    def explain(self, query: ValidatedReadQuery) -> dict[str, Any]:
        self._ensure_query(query)
        connection = self._require_connection()
        with self._lock:
            self._start_query("explain")
            try:
                cursor = connection.execute("EXPLAIN QUERY PLAN " + query._sql)
                rows = cursor.fetchmany(self.grant.budget.max_plan_rows + 1)
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
                raise DatabaseGateError("sqlite_explain_denied_or_failed") from exc
            finally:
                self._finish_query()
        if len(rows) > self.grant.budget.max_plan_rows:
            raise DatabaseGateError("sqlite_explain_plan_limit_exceeded")
        self._assert_observed_reads(query)
        rendered = json.dumps(rows, ensure_ascii=True, separators=(",", ":"), default=str)
        return {
            "schema": "k_guard_sqlite_explain.v1",
            "plan_row_count": len(rows),
            "plan_sha256": hashlib.sha256(rendered.encode("ascii")).hexdigest(),
            "observed_read_count": len(self._observed_reads),
            "raw_free": True,
        }

    def list_tables(self, *, max_tables: int = 50) -> list[str]:
        if max_tables <= 0 or max_tables > 256:
            raise DatabaseGateError("sqlite_catalog_table_limit_invalid")
        connection = self._require_connection()
        with self._lock:
            self._start_query("catalog")
            try:
                rows = connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT ?",
                    (max_tables + 1,),
                ).fetchmany(max_tables + 1)
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
                raise DatabaseGateError("sqlite_catalog_denied_or_failed") from exc
            finally:
                self._finish_query()
        if len(rows) > max_tables:
            raise DatabaseGateError("sqlite_catalog_table_limit_exceeded")
        result: list[str] = []
        for row in rows:
            try:
                result.append(_identifier(row[0], "table"))
            except (IndexError, TypeError, ValueError) as exc:
                raise DatabaseGateError("sqlite_catalog_identifier_invalid") from exc
        return result

    def list_columns(self, table: str, *, max_columns: int = 256) -> list[str]:
        normalized_table = _identifier(table, "table")
        if max_columns <= 0 or max_columns > 512:
            raise DatabaseGateError("sqlite_catalog_column_limit_invalid")
        connection = self._require_connection()
        with self._lock:
            self._catalog_table = normalized_table
            self._start_query("catalog")
            try:
                rows = connection.execute(
                    f"PRAGMA table_info({_quote_sqlite_identifier(normalized_table)})"
                ).fetchmany(max_columns + 1)
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
                raise DatabaseGateError("sqlite_catalog_denied_or_failed") from exc
            finally:
                self._catalog_table = ""
                self._finish_query()
        if len(rows) > max_columns:
            raise DatabaseGateError("sqlite_catalog_column_limit_exceeded")
        result: list[str] = []
        for row in rows:
            try:
                result.append(_identifier(row[1], "column"))
            except (IndexError, TypeError, ValueError) as exc:
                raise DatabaseGateError("sqlite_catalog_identifier_invalid") from exc
        return result

    def execute_read(self, query: ValidatedReadQuery) -> list[tuple[Any, ...]]:
        self._ensure_query(query)
        connection = self._require_connection()
        with self._lock:
            self._start_query("execute")
            rows: list[tuple[Any, ...]] = []
            total_bytes = 0
            try:
                cursor = connection.execute(query._sql)
                while True:
                    batch = cursor.fetchmany(min(25, self.grant.budget.max_rows + 1 - len(rows)))
                    if not batch:
                        break
                    for raw_row in batch:
                        row = tuple(raw_row)
                        for value in row:
                            cell_bytes = len(str(value).encode("utf-8", errors="replace"))
                            if cell_bytes > self.grant.budget.max_cell_bytes:
                                raise DatabaseGateError("sqlite_cell_budget_exceeded")
                            total_bytes += cell_bytes
                        if total_bytes > self.grant.budget.max_result_bytes:
                            raise DatabaseGateError("sqlite_result_budget_exceeded")
                        rows.append(row)
                        if len(rows) > query.limit or len(rows) > self.grant.budget.max_rows:
                            raise DatabaseGateError("sqlite_row_budget_exceeded")
            except DatabaseGateError:
                raise
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
                raise DatabaseGateError("sqlite_read_denied_or_failed") from exc
            finally:
                self._finish_query()
        self._assert_observed_reads(query)
        return rows

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None or self._phase == "closed":
            raise DatabaseGateError("sqlite_session_not_open")
        return self._connection

    def _ensure_query(self, query: ValidatedReadQuery) -> None:
        if query.schema != self.grant.schema or query.table != self.grant.table:
            raise DatabaseGateError("sqlite_query_grant_mismatch")
        if set(query.columns) - set(self.grant.columns) or query.limit > self.grant.budget.max_rows:
            raise DatabaseGateError("sqlite_query_grant_mismatch")

    def _start_query(self, phase: str) -> None:
        self._phase = phase
        self._deadline = time.monotonic() + self.grant.budget.timeout_seconds
        self._steps = 0
        self._observed_reads.clear()

    def _finish_query(self) -> None:
        self._phase = "ready"
        self._deadline = 0.0

    def _progress(self) -> int:
        self._steps += 100
        return int(self._steps > self.grant.budget.max_vm_steps or time.monotonic() > self._deadline)

    def _authorize(self, action: int, arg1: str | None, arg2: str | None, database: str | None, source: str | None) -> int:
        del source
        if self._phase == "catalog":
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ:
                table = _safe_sqlite_identifier(arg1)
                column = _safe_sqlite_identifier(arg2)
                if table == "sqlite_master" and column in {"name", "type"}:
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and _safe_sqlite_identifier(arg2 or arg1) == "like":
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA:
                pragma = _safe_sqlite_identifier(arg1)
                target = _safe_sqlite_identifier(arg2)
                if pragma == "table_info" and target == self._catalog_table:
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_DENY
        if self._phase not in {"explain", "execute"}:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            table = _safe_sqlite_identifier(arg1)
            column = _safe_sqlite_identifier(arg2)
            schema = _safe_sqlite_identifier(database or "main")
            if schema != self.grant.schema or table != self.grant.table or column not in self.grant.columns:
                return sqlite3.SQLITE_DENY
            self._observed_reads.add((table, column))
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def _assert_observed_reads(self, query: ValidatedReadQuery) -> None:
        observed = {column for table, column in self._observed_reads if table == query.table}
        if not observed or not observed.issubset(set(self.grant.columns)):
            raise DatabaseGateError("sqlite_observed_read_mismatch")


def build_database_gate_report(
    sql: str,
    *,
    dialect: str,
    principal: DbPrincipal,
    grant: TableGrant,
    database: str,
) -> dict[str, Any]:
    ast_decision = SqlAstGate().validate(sql, dialect=dialect, budget=grant.budget)
    if not ast_decision.allowed or ast_decision.query is None:
        return ast_decision.to_report(policy_ref=evidence_hash(f"{grant.role}:{grant.database}:{grant.schema}:{grant.table}"))
    rbac_decision = RbacGate().authorize(ast_decision.query, principal, grant, database=database)
    return rbac_decision.to_report(policy_ref=evidence_hash(f"{grant.role}:{grant.database}:{grant.schema}:{grant.table}"))


def _deny(code: str, checks: Sequence[dict[str, Any]], query: ValidatedReadQuery | None = None) -> QueryDecision:
    return QueryDecision(False, code, query, tuple((*checks, _check(code, False, code))))


def _check(name: str, passed: bool, observed: Any) -> dict[str, Any]:
    safe_observed: str | int | float | bool | None
    if isinstance(observed, (str, int, float, bool)) or observed is None:
        safe_observed = observed
    else:
        safe_observed = evidence_hash(json.dumps(observed, sort_keys=True, default=str))
    return {"name": name, "passed": bool(passed), "observed": safe_observed, "raw_free": True}


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip().casefold()
    if not text or len(text) > 128 or not all(character.isalnum() or character in {"_", "-"} for character in text):
        raise ValueError(f"{label} identifier is invalid")
    return text


def _safe_sqlite_identifier(value: Any) -> str:
    try:
        return _identifier(value, "sqlite")
    except ValueError:
        return ""


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _contained_database(path_value: str | Path, root_value: str | Path, budget: QueryBudget) -> Path:
    try:
        root = Path(root_value)
        candidate = Path(path_value)
        if root.is_symlink() or candidate.is_symlink():
            raise DatabaseGateError("sqlite_symlink_disallowed")
        root = root.resolve(strict=True)
        candidate = candidate.resolve(strict=True)
        if not root.is_dir() or not candidate.is_file():
            raise DatabaseGateError("sqlite_path_invalid")
        candidate.relative_to(root)
        size = candidate.stat().st_size
    except DatabaseGateError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise DatabaseGateError("sqlite_path_outside_root_or_invalid") from exc
    if size <= 0 or size > budget.max_database_bytes:
        raise DatabaseGateError("sqlite_database_size_invalid")
    return candidate


def _create_sqlite_snapshot(
    path: Path,
    *,
    root: Path,
    budget: QueryBudget,
) -> tuple[tempfile.TemporaryDirectory[str], Path, tuple[tuple[str, int, str], ...]]:
    source_manifest = _sqlite_source_manifest(path, budget)
    snapshot_directory = tempfile.TemporaryDirectory(prefix="k-guard-sqlite-snapshot-")
    try:
        snapshot_root = Path(snapshot_directory.name).resolve(strict=True)
        if snapshot_root == root or snapshot_root.is_relative_to(root):
            raise DatabaseGateError("sqlite_snapshot_root_inside_scan_root")
        snapshot_path = snapshot_root / path.name
        expected = {suffix: (size, digest) for suffix, size, digest in source_manifest}
        for suffix in SQLITE_SNAPSHOT_COPY_SUFFIXES:
            source_contract = expected.get(suffix)
            if source_contract is None:
                continue
            source = _sqlite_member_path(path, suffix)
            destination = _sqlite_member_path(snapshot_path, suffix)
            shutil.copyfile(source, destination)
            expected_size, expected_sha256 = source_contract
            if (
                destination.stat().st_size != expected_size
                or _sha256_file(destination) != expected_sha256
            ):
                raise DatabaseGateError("sqlite_snapshot_copy_mismatch")
        if _sqlite_source_manifest(path, budget) != source_manifest:
            raise DatabaseGateError("sqlite_source_changed_during_snapshot")
        return snapshot_directory, snapshot_path, source_manifest
    except DatabaseGateError:
        snapshot_directory.cleanup()
        raise
    except (OSError, RuntimeError) as exc:
        snapshot_directory.cleanup()
        raise DatabaseGateError("sqlite_snapshot_copy_failed") from exc


def _sqlite_source_manifest(
    path: Path,
    budget: QueryBudget,
) -> tuple[tuple[str, int, str], ...]:
    rows: list[tuple[str, int, str]] = []
    total_bytes = 0
    for suffix in SQLITE_SOURCE_MEMBER_SUFFIXES:
        member = _sqlite_member_path(path, suffix)
        if member.is_symlink():
            raise DatabaseGateError("sqlite_snapshot_sidecar_symlink_disallowed")
        try:
            exists = member.exists()
        except OSError as exc:
            raise DatabaseGateError("sqlite_snapshot_source_stat_failed") from exc
        if not exists:
            continue
        try:
            if not member.is_file() or member.resolve(strict=True) != member:
                raise DatabaseGateError("sqlite_snapshot_source_invalid")
            size = member.stat().st_size
        except DatabaseGateError:
            raise
        except (OSError, RuntimeError) as exc:
            raise DatabaseGateError("sqlite_snapshot_source_stat_failed") from exc
        if size < 0 or size > budget.max_database_bytes or (suffix == "" and size == 0):
            raise DatabaseGateError("sqlite_snapshot_member_size_invalid")
        total_bytes += size
        rows.append((suffix, size, _sha256_file(member)))
    if not rows or rows[0][0] != "":
        raise DatabaseGateError("sqlite_snapshot_main_database_missing")
    if total_bytes > budget.max_database_bytes * len(SQLITE_SOURCE_MEMBER_SUFFIXES):
        raise DatabaseGateError("sqlite_snapshot_total_size_invalid")
    return tuple(rows)


def _sqlite_member_path(path: Path, suffix: str) -> Path:
    return path if not suffix else Path(str(path) + suffix)


def _apply_sqlite_limits(connection: sqlite3.Connection, budget: QueryBudget) -> None:
    if not hasattr(connection, "setlimit"):
        raise DatabaseGateError("sqlite_limits_unavailable")
    limits = (
        (sqlite3.SQLITE_LIMIT_LENGTH, budget.max_cell_bytes),
        (sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_BYTES),
        (sqlite3.SQLITE_LIMIT_COLUMN, 256),
        (sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 1),
        (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
        (sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 256),
        (sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64),
    )
    for category, value in limits:
        connection.setlimit(category, value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise DatabaseGateError("sqlite_hash_failed") from exc
    return digest.hexdigest()


try:
    from sqlglot.tokens import TokenError
except ImportError:  # pragma: no cover - pinned SQLGlot exports TokenError.
    TokenError = ValueError  # type: ignore[misc,assignment]


__all__ = [
    "DATABASE_GATE_SCHEMA",
    "DATABASE_VALIDATION_SCHEMA",
    "DatabaseGateError",
    "DbPrincipal",
    "QueryBudget",
    "QueryDecision",
    "RbacGate",
    "SqlAstGate",
    "SqliteReadOnlySession",
    "TableGrant",
    "ValidatedReadQuery",
    "build_database_gate_report",
]
