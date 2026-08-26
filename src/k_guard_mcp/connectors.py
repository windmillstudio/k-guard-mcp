from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from k_guard_mcp.collector import DEFAULT_EXCLUDES, collect_files, read_text
from k_guard_mcp.detectors import PiiDetector, SecretDetector
from k_guard_mcp.database_gate import (
    DatabaseGateError,
    DbPrincipal,
    QueryBudget,
    RbacGate,
    SqlAstGate,
    SqliteReadOnlySession,
    TableGrant,
)
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding
from k_guard_mcp.privacy_taxonomy import metadata_for_labels


SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
STORAGE_SUFFIXES = {".json", ".csv", ".tsv"}
MAX_SQLITE_FILES = 50
SENSITIVE_COLUMN = re.compile(
    r"(email|phone|name|address|rrn|frn|passport|ci|di|birth|patient|medical|"
    r"account|card|token|secret|password|api[_-]?key|주민|전화|이메일|주소|이름|환자|진료|계좌)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ConnectorScanResult:
    findings: tuple[Finding, ...]
    evidence: dict[str, Any]


class ReadOnlyConnectorScanner:
    def __init__(self, id_factory: IdFactory | None = None, max_sample_rows: int = 25, max_file_bytes: int = 2 * 1024 * 1024) -> None:
        self.ids = id_factory or IdFactory()
        self.max_sample_rows = max_sample_rows
        self.max_file_bytes = max_file_bytes
        self.pii_detector = PiiDetector(self.ids)
        self.secret_detector = SecretDetector(self.ids)

    def scan(self, root: str | Path) -> list[Finding]:
        return list(self.scan_with_evidence(root).findings)

    def scan_with_evidence(self, root: str | Path) -> ConnectorScanResult:
        findings: list[Finding] = []
        failures: list[tuple[str, str]] = []
        try:
            entry = Path(root)
            if entry.is_symlink():
                raise DatabaseGateError("connector_root_symlink_disallowed")
            base = entry.resolve(strict=True)
        except (OSError, RuntimeError, ValueError, DatabaseGateError) as exc:
            code = exc.code if isinstance(exc, DatabaseGateError) else "connector_root_invalid"
            finding = self._coverage_finding(code, Path(str(root or ".")))
            return ConnectorScanResult(
                findings=(finding,),
                evidence=_connector_evidence(0, 0, 0, 1, [code]),
            )

        sqlite_files, discovery_failures = self._discover_sqlite_files(base)
        failures.extend(discovery_failures)
        inspected_databases = 0
        inspected_tables = 0
        sampled_tables = 0
        for path in sqlite_files:
            inspected_databases += 1
            partial, table_count, sample_count, error = self._scan_sqlite_file(path, base if base.is_dir() else base.parent)
            findings.extend(partial)
            inspected_tables += table_count
            sampled_tables += sample_count
            if error:
                failures.append((error, str(path)))

        storage_findings, storage_failures = self._scan_log_and_storage_files(base)
        findings.extend(storage_findings)
        failures.extend(storage_failures)
        for code, path in failures:
            findings.append(self._coverage_finding(code, Path(path)))
        evidence = _connector_evidence(
            len(sqlite_files),
            inspected_tables,
            sampled_tables,
            len(failures),
            [code for code, _path in failures],
        )
        return ConnectorScanResult(findings=tuple(findings), evidence=evidence)

    def _discover_sqlite_files(self, base: Path) -> tuple[list[Path], list[tuple[str, str]]]:
        files: list[Path] = []
        failures: list[tuple[str, str]] = []
        if base.is_file() and base.suffix.lower() in SQLITE_SUFFIXES:
            try:
                if base.is_symlink():
                    failures.append(("sqlite_symlink_disallowed", str(base)))
                elif base.stat().st_size <= 0 or base.stat().st_size > self.max_file_bytes:
                    failures.append(("sqlite_database_size_invalid", str(base)))
                else:
                    files.append(base)
            except OSError:
                failures.append(("sqlite_discovery_stat_failed", str(base)))
        if base.is_dir():
            for current_root, directory_names, file_names in os.walk(base, topdown=True, followlinks=False):
                kept: list[str] = []
                for name in sorted(directory_names):
                    candidate = Path(current_root) / name
                    if name in DEFAULT_EXCLUDES:
                        continue
                    if candidate.is_symlink():
                        failures.append(("sqlite_symlink_tree_disallowed", str(candidate)))
                        continue
                    kept.append(name)
                directory_names[:] = kept
                current = Path(current_root)
                for name in sorted(file_names):
                    path = current / name
                    if path.suffix.lower() not in SQLITE_SUFFIXES:
                        continue
                    try:
                        if path.is_symlink():
                            failures.append(("sqlite_symlink_disallowed", str(path)))
                        elif path.stat().st_size <= 0 or path.stat().st_size > self.max_file_bytes:
                            failures.append(("sqlite_database_size_invalid", str(path)))
                        else:
                            files.append(path)
                    except OSError:
                        failures.append(("sqlite_discovery_stat_failed", str(path)))
                    if len(files) > MAX_SQLITE_FILES:
                        failures.append(("sqlite_database_count_limit_exceeded", str(base)))
                        files = files[:MAX_SQLITE_FILES]
                        return files, failures
        return files, failures

    def _scan_sqlite_file(self, path: Path, root: Path) -> tuple[list[Finding], int, int, str]:
        findings: list[Finding] = []
        budget = QueryBudget(
            max_rows=self.max_sample_rows,
            max_database_bytes=self.max_file_bytes,
            max_result_bytes=self.max_file_bytes,
        )
        catalog_grant = TableGrant(
            role="catalog-reader",
            database="local-sqlite",
            schema="main",
            table="sqlite_master",
            columns=frozenset({"name", "type"}),
            budget=budget,
        )
        try:
            with SqliteReadOnlySession(path, root=root, grant=catalog_grant) as catalog:
                tables = catalog.list_tables(max_tables=50)
                table_columns = {table: catalog.list_columns(table) for table in tables}
            sampled = 0
            for table, columns in table_columns.items():
                sensitive_columns = [column for column in columns if SENSITIVE_COLUMN.search(str(column))]
                if sensitive_columns:
                    findings.append(
                        Finding(
                            id=self.ids.next(),
                            source="connector",
                            rule_id="CONNECTOR_SQLITE_SENSITIVE_SCHEMA",
                            severity="medium",
                            confidence="medium",
                            title="SQLite schema contains personal-data columns",
                            file=str(path),
                            evidence=f"table_hash={evidence_hash(table)} sensitive_column_count={len(sensitive_columns)} scheme={evidence_hash_scheme()}",
                            why_it_matters="A local database schema appears to store personal data and should have access, retention, and deletion controls.",
                            recommendation="Confirm the database is not committed, is encrypted if needed, and has retention/deletion handling.",
                            audit_depth=4,
                            inspected_scope="A byte-bound detached SQLite snapshot was opened read-only and table/column names were inspected without writing the source database or its sidecars.",
                            not_inspected="Only local SQLite files under the scan path were inspected; remote databases and full row histories were not accessed.",
                        )
                    )
                if not columns:
                    continue
                table_grant = TableGrant(
                    role="table-sampler",
                    database="local-sqlite",
                    schema="main",
                    table=table,
                    columns=frozenset(columns),
                    budget=budget,
                )
                column_sql = ", ".join(_quote_identifier(column) for column in columns)
                sql = f"SELECT {column_sql} FROM {_quote_identifier(table)} LIMIT {self.max_sample_rows}"
                ast_decision = SqlAstGate().validate(sql, dialect="sqlite", budget=budget)
                if not ast_decision.allowed or ast_decision.query is None:
                    raise DatabaseGateError(ast_decision.code)
                rbac = RbacGate().authorize(
                    ast_decision.query,
                    DbPrincipal(evidence_hash(str(path)), frozenset({"table-sampler"})),
                    table_grant,
                    database="local-sqlite",
                )
                if not rbac.allowed:
                    raise DatabaseGateError(rbac.code)
                with SqliteReadOnlySession(path, root=root, grant=table_grant) as session:
                    session.explain(ast_decision.query)
                    rows = session.execute_read(ast_decision.query)
                sampled += 1
                findings.extend(self._scan_sqlite_rows(path, table, columns, rows))
        except DatabaseGateError as exc:
            return findings, 0, 0, exc.code
        except Exception:
            return findings, 0, 0, "sqlite_unexpected_control_failure"
        return findings, len(tables), sampled, ""

    def _scan_sqlite_rows(self, path: Path, table: str, columns: list[str], rows: list[tuple[Any, ...]]) -> list[Finding]:
        findings: list[Finding] = []
        if not rows:
            return findings
        labels: Counter[str] = Counter()
        secret_rules: Counter[str] = Counter()
        for row in rows:
            record = {str(columns[index] if index < len(columns) else f"col_{index}"): value for index, value in enumerate(row)}
            text = json.dumps(record, ensure_ascii=False, default=str)
            for entity in self.pii_detector.detect_entities(text, str(path)):
                labels[entity.label] += 1
            for finding in self.secret_detector.scan_text(text, str(path)):
                secret_rules[finding.rule_id] += 1
        if labels:
            meta = metadata_for_labels(labels.keys(), audit_depth=5)
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="connector",
                    rule_id="CONNECTOR_SQLITE_PII_AT_REST",
                    severity="high",
                    confidence="medium",
                    title="SQLite sample rows contain personal data",
                    file=str(path),
                    evidence=f"table_hash={evidence_hash(table)} sampled_rows={len(rows)} pii_counts={_format_counts(labels)} scheme={evidence_hash_scheme()}",
                    why_it_matters="Personal data at rest creates access-control, retention, and deletion obligations beyond code-level scanning.",
                    recommendation="Verify this database is a local fixture or protected runtime database, minimize stored fields, and define deletion/retention controls.",
                    privacy_class=str(meta["privacy_class"]),
                    pipc_basis=str(meta["pipc_basis"]),
                    audit_depth=int(meta["audit_depth"]),
                    inspected_scope="A byte-bound detached SQLite snapshot was opened read-only; sample rows were classified locally and raw values were not stored.",
                    not_inspected="Only a bounded row sample was inspected; remote production DBs and historical backups were not connected.",
                )
            )
        if secret_rules:
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="connector",
                    rule_id="CONNECTOR_SQLITE_SECRET_AT_REST",
                    severity="critical",
                    confidence="medium",
                    title="SQLite sample rows contain secret-like data",
                    file=str(path),
                    evidence=f"table_hash={evidence_hash(table)} sampled_rows={len(rows)} secret_counts={_format_counts(secret_rules)} scheme={evidence_hash_scheme()}",
                    why_it_matters="Secrets stored in local databases can leak through backups, fixtures, or developer machines.",
                    recommendation="Remove the secret from the database, rotate it if real, and use a dedicated secret store.",
                    audit_depth=5,
                    inspected_scope="A byte-bound detached SQLite snapshot was opened read-only and sample rows were scanned for secret patterns without storing raw values.",
                    not_inspected="The scanner did not validate whether the credential is live or inspect remote secret stores.",
                )
            )
        return findings

    def _scan_log_and_storage_files(self, base: Path) -> tuple[list[Finding], list[tuple[str, str]]]:
        findings: list[Finding] = []
        failures: list[tuple[str, str]] = []
        for path in collect_files(base):
            suffix = path.suffix.lower()
            if suffix not in {".log", *STORAGE_SUFFIXES}:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                failures.append(("storage_stat_failed", str(path)))
                continue
            if size > self.max_file_bytes:
                failures.append(("storage_size_limit_exceeded", str(path)))
                continue
            try:
                text = read_text(path, max_bytes=self.max_file_bytes)
            except OSError:
                failures.append(("storage_read_failed", str(path)))
                continue
            if text is None:
                failures.append(("storage_decode_failed", str(path)))
                continue
            if not text:
                continue
            labels = Counter(entity.label for entity in self.pii_detector.detect_entities(text, str(path)))
            secret_findings = self.secret_detector.scan_text(text, str(path))
            secret_rules = Counter(finding.rule_id for finding in secret_findings)
            if labels:
                meta = metadata_for_labels(labels.keys(), audit_depth=4)
                rule_id = "CONNECTOR_LOG_PII_AT_REST" if suffix == ".log" else "CONNECTOR_STORAGE_PII_AT_REST"
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="connector",
                        rule_id=rule_id,
                        severity="high" if suffix == ".log" else "medium",
                        confidence="medium",
                        title="Read-only connector found personal data at rest",
                        file=str(path),
                        evidence=f"file_hash={evidence_hash(str(path))} pii_counts={_format_counts(labels)} scheme={evidence_hash_scheme()}",
                        why_it_matters="Personal data in logs or storage fixtures can be retained, copied, or uploaded outside normal app controls.",
                        recommendation="Replace with synthetic data, mask fields, and define retention/deletion controls for this storage surface.",
                        privacy_class=str(meta["privacy_class"]),
                        pipc_basis=str(meta["pipc_basis"]),
                        audit_depth=int(meta["audit_depth"]),
                        inspected_scope="Local log/storage file was read-only scanned with count-only PII classification.",
                        not_inspected="The scanner did not inspect remote logs, object storage buckets, or production retention jobs.",
                    )
                )
            if secret_rules:
                severity = min(
                    (finding.severity for finding in secret_findings),
                    key={"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get,
                )
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="connector",
                        rule_id="CONNECTOR_SECRET_AT_REST",
                        severity=severity,
                        confidence="medium",
                        title="Read-only connector found secret-like data at rest",
                        file=str(path),
                        evidence=f"file_hash={evidence_hash(str(path))} secret_counts={_format_counts(secret_rules)} scheme={evidence_hash_scheme()}",
                        why_it_matters="Secrets in logs or storage files can leak through backups, support bundles, or source control.",
                        recommendation="Remove and rotate the secret if real, then prevent the value from reaching logs/storage.",
                        audit_depth=4,
                        inspected_scope="Local log/storage file was read-only scanned for secret patterns.",
                        not_inspected="The scanner did not validate credential liveness or inspect remote secret stores.",
                    )
                )
        return findings, failures

    def _coverage_finding(self, code: str, path: Path) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="connector",
            rule_id="CONNECTOR_LOCAL_STORAGE_COVERAGE_INCOMPLETE",
            severity="high",
            confidence="high",
            title="Local storage inspection did not complete",
            file=str(path),
            evidence=f"control_code={code} path_ref={evidence_hash(str(path))} raw_returned=false",
            why_it_matters="Unreadable, oversized, linked, changed, or policy-denied storage must not silently count as reviewed.",
            recommendation="Remove the coverage blocker or narrow the authorized storage scope, then rerun the same review.",
            audit_depth=5,
            inspected_scope="Storage discovery, containment, read-only policy, query limits, and parse/read completion were checked fail-closed.",
            not_inspected="The blocked storage content was not treated as safe and no raw value was returned.",
        )


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _format_counts(counts: Counter[str]) -> str:
    return ",".join(f"{key}={counts[key]}" for key in sorted(counts))


def _connector_evidence(
    database_count: int,
    table_count: int,
    sampled_table_count: int,
    failure_count: int,
    failure_codes: list[str],
) -> dict[str, Any]:
    return {
        "schema": "k_guard_connector_coverage.v2",
        "complete": failure_count == 0,
        "fail_closed": True,
        "database_count": database_count,
        "table_count": table_count,
        "sampled_table_count": sampled_table_count,
        "failure_count": failure_count,
        "failure_code_counts": dict(sorted(Counter(failure_codes).items())),
        "database_controls": [
            "contained_non_symlink_path",
            "sql_ast_single_bounded_select",
            "rbac_exact_table_columns",
            "sqlite_explain_query_plan",
            "mode_ro_query_only_authorizer",
            "detached_source_snapshot_with_wal_sidecars",
            "source_sidecar_before_after_hash",
            "vm_row_cell_result_budgets",
            "before_after_content_hash",
        ],
        "raw_returned": False,
    }


__all__ = ["ConnectorScanResult", "ReadOnlyConnectorScanner"]
