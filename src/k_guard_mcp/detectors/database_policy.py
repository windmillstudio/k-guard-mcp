from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterator

from sqlglot import Dialect, ErrorLevel, exp, parse_one
from sqlglot.errors import ParseError, TokenError
from sqlglot.tokens import Token, TokenType

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding


MAX_SQL_BYTES = 2 * 1024 * 1024
MAX_SQL_TOKENS = 120_000
MAX_SQL_STATEMENTS = 2_000
MAX_STATEMENT_BYTES = 256 * 1024
MAX_TRACKED_TABLES = 2_000
MAX_POLICY_FINDINGS = 256

_SQLGLOT_COMMAND_FALLBACK = "contains unsupported syntax. Falling back to parsing as a 'Command'."

_TARGET_ROLES = frozenset({"anon", "authenticated", "public"})
_DATA_PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
_WRITE_PRIVILEGES = frozenset({"INSERT", "UPDATE", "DELETE"})
_ELEVATED_PRIVILEGES = frozenset({"TRUNCATE", "TRIGGER", "REFERENCES"})
_MANAGED_SCHEMAS = frozenset({"auth", "extensions", "graphql", "graphql_public", "information_schema", "pg_catalog", "realtime", "storage", "supabase_migrations", "vault"})
_MIGRATION_TABLES = frozenset({"_prisma_migrations", "flyway_schema_history", "knex_migrations", "schema_migrations", "supabase_migrations"})
_TEST_PARTS = frozenset({"test", "tests", "fixture", "fixtures", "__tests__", "spec", "specs"})
_DOC_PARTS = frozenset({"doc", "docs", "documentation"})
_MIGRATION_PARTS = frozenset({"migration", "migrations", "schema", "schemas", "supabase"})
_POSTGRES_PATH_PARTS = frozenset({"postgres", "postgresql", "psql", "supabase"})
_POSTGRES_TYPE_MARKERS = frozenset({"BIGSERIAL", "CITEXT", "INET", "JSONB", "PLPGSQL", "SERIAL", "TIMESTAMPTZ", "TSVECTOR"})
_FUNCTION_OPTION_WORDS = frozenset(
    {
        "AS",
        "CALLED",
        "COST",
        "DEFINER",
        "IMMUTABLE",
        "LANGUAGE",
        "LEAKPROOF",
        "PARALLEL",
        "RETURNS",
        "ROWS",
        "SECURITY",
        "SQL SECURITY",
        "STABLE",
        "STRICT",
        "SUPPORT",
        "TRANSFORM",
        "VOLATILE",
        "WINDOW",
    }
)


class _SqlglotCommandFallbackFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return _SQLGLOT_COMMAND_FALLBACK not in record.getMessage()


@contextmanager
def _quiet_sqlglot_command_fallback() -> Iterator[None]:
    """Keep raw unsupported SQL out of console logs; coverage remains in findings."""

    logger = logging.getLogger("sqlglot")
    log_filter = _SqlglotCommandFallbackFilter()
    logger.addFilter(log_filter)
    try:
        yield
    finally:
        logger.removeFilter(log_filter)

RelationKey = tuple[str, str, str]


@dataclass(frozen=True)
class _SqlStatement:
    text: str
    tokens: tuple[Token, ...]
    line: int

    @property
    def statement_ref(self) -> str:
        return evidence_hash(self.text)


@dataclass(frozen=True)
class _CreatedTable:
    key: RelationKey
    line: int
    statement_ref: str


class _CoverageError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DatabasePolicyDetector:
    """Bounded PostgreSQL/Supabase migration review with raw-free evidence."""

    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        if not _is_sql_file(file):
            return []

        artifact_scope = _artifact_scope(file)
        byte_count = len(text.encode("utf-8", errors="ignore"))
        pre_context = _raw_postgres_context_hint(text, file)
        if byte_count > MAX_SQL_BYTES:
            return [self._coverage_finding("input_byte_limit_exceeded", text, file, artifact_scope)] if pre_context else []

        try:
            statements = _split_statements(text)
        except TokenError:
            return [self._coverage_finding("tokenization_incomplete", text, file, artifact_scope)] if pre_context else []
        except _CoverageError as error:
            return [self._coverage_finding(error.reason, text, file, artifact_scope)] if pre_context else []

        postgres_context = _postgres_context(statements, file) or pre_context
        rls_expected = _rls_expected_context(statements, text, file)
        findings: list[Finding] = []
        coverage_reasons: set[str] = set()
        created_tables: dict[RelationKey, _CreatedTable] = {}
        enabled_rls: set[RelationKey] = set()
        disabled_rls: set[RelationKey] = set()

        def add(finding: Finding) -> None:
            if len(findings) >= MAX_POLICY_FINDINGS - 1:
                coverage_reasons.add("finding_limit_exceeded")
                return
            findings.append(finding)

        for statement in statements:
            statement_bytes = len(statement.text.encode("utf-8", errors="ignore"))
            if statement_bytes > MAX_STATEMENT_BYTES:
                coverage_reasons.add("statement_byte_limit_exceeded")
                continue

            words = _words(statement.tokens)
            if _is_rls_statement(words):
                parsed_rls = _parse_rls_statement(statement.tokens)
                if parsed_rls is None:
                    coverage_reasons.add("rls_syntax_unresolved")
                    continue
                action, table_key, line = parsed_rls
                if action == "enable":
                    enabled_rls.add(table_key)
                else:
                    disabled_rls.add(table_key)
                    add(
                        self._finding(
                            rule_id="DB_POLICY_RLS_DISABLED",
                            severity="critical",
                            subtype="row_level_security_disabled",
                            title="Row-level security is explicitly disabled",
                            why_it_matters="An explicit RLS disable can expose every row allowed by table grants and bypass policy assumptions.",
                            recommendation="Remove the disable, enable RLS, and verify least-privilege policies for every application role before release.",
                            object_key=table_key,
                            statement=statement,
                            file=file,
                            line=line,
                            artifact_scope=artifact_scope,
                        )
                    )
                continue

            if _is_create_policy(words):
                policy_result = _parse_policy_statement(statement.tokens)
                if policy_result is None:
                    coverage_reasons.add("policy_syntax_unresolved")
                    continue
                table_key, permissive_true_clauses = policy_result
                for subtype, line in permissive_true_clauses:
                    add(
                        self._finding(
                            rule_id="DB_POLICY_PERMISSIVE_TRUE",
                            severity="critical",
                            subtype=subtype,
                            title="A permissive row policy accepts every row",
                            why_it_matters="A permissive true predicate removes row ownership or tenant isolation for every role covered by the policy.",
                            recommendation="Replace the unconditional predicate with an authenticated owner, tenant, or narrowly scoped service condition and test denied access.",
                            object_key=table_key,
                            statement=statement,
                            file=file,
                            line=line,
                            artifact_scope=artifact_scope,
                        )
                    )
                continue

            if _is_create_function(words):
                function_result = _analyze_security_definer_function(statement.tokens)
                if function_result is None:
                    coverage_reasons.add("security_definer_syntax_unresolved")
                    continue
                function_key, security_definer, fixed_search_path, line = function_result
                if security_definer and not fixed_search_path:
                    add(
                        self._finding(
                            rule_id="DB_POLICY_SECURITY_DEFINER_SEARCH_PATH",
                            severity="high",
                            subtype="security_definer_without_fixed_search_path",
                            title="Security-definer function has no fixed search path",
                            why_it_matters="A privileged function that resolves unqualified objects through a mutable search path can execute attacker-controlled objects with definer rights.",
                            recommendation="Set a function-local, literal search_path and schema-qualify privileged object references before release.",
                            object_key=function_key,
                            statement=statement,
                            file=file,
                            line=line,
                            artifact_scope=artifact_scope,
                        )
                    )
                continue

            if _is_all_tables_grant(words):
                grant_result = _parse_all_tables_grant(statement.tokens)
                if grant_result is None:
                    coverage_reasons.add("grant_syntax_unresolved")
                    continue
                object_key, target_roles, line = grant_result
                if target_roles:
                    add(
                        self._grant_finding(
                            subtype="all_tables_in_schema",
                            object_key=object_key,
                            principal_count=len(target_roles),
                            statement=statement,
                            file=file,
                            line=line,
                            artifact_scope=artifact_scope,
                        )
                    )
                continue

            try:
                with _quiet_sqlglot_command_fallback():
                    expression = parse_one(statement.text, read="postgres", error_level=ErrorLevel.RAISE)
            except ParseError:
                if postgres_context:
                    coverage_reasons.add("statement_parse_error")
                continue

            if isinstance(expression, exp.Create) and str(expression.args.get("kind") or "").upper() == "TABLE":
                created = _created_table(expression, statement)
                if created is not None and _is_application_table(created.key):
                    if len(created_tables) >= MAX_TRACKED_TABLES and created.key not in created_tables:
                        coverage_reasons.add("table_tracking_limit_exceeded")
                    else:
                        created_tables.setdefault(created.key, created)
            elif isinstance(expression, exp.Grant):
                grant = _grant_from_ast(expression)
                if grant is not None:
                    object_key, target_roles, subtype = grant
                    add(
                        self._grant_finding(
                            subtype=subtype,
                            object_key=object_key,
                            principal_count=len(target_roles),
                            statement=statement,
                            file=file,
                            line=statement.line,
                            artifact_scope=artifact_scope,
                        )
                    )
            elif isinstance(expression, exp.Command) and _security_relevant(words):
                coverage_reasons.add("security_statement_unsupported")

        if postgres_context and rls_expected:
            for table_key, created in sorted(created_tables.items()):
                if table_key in enabled_rls or table_key in disabled_rls:
                    continue
                add(
                    self._finding(
                        rule_id="DB_POLICY_RLS_MISSING",
                        severity="high",
                        subtype="created_application_table_missing_rls",
                        title="Created application table has no RLS enablement",
                        why_it_matters="A PostgreSQL/Supabase application table without RLS can return or mutate rows outside the caller's ownership boundary.",
                        recommendation="Enable row-level security in the migration and add explicit least-privilege policies before granting application roles access.",
                        object_key=table_key,
                        statement_ref=created.statement_ref,
                        file=file,
                        line=created.line,
                        artifact_scope=artifact_scope,
                    )
                )

        if coverage_reasons and postgres_context:
            primary_reason = sorted(coverage_reasons)[0]
            findings.append(
                self._coverage_finding(
                    primary_reason,
                    text,
                    file,
                    artifact_scope,
                    reason_count=len(coverage_reasons),
                    reason_set_ref=evidence_hash("|".join(sorted(coverage_reasons))),
                )
            )
        return findings

    def _grant_finding(
        self,
        *,
        subtype: str,
        object_key: RelationKey,
        principal_count: int,
        statement: _SqlStatement,
        file: str | None,
        line: int,
        artifact_scope: str,
    ) -> Finding:
        return self._finding(
            rule_id="DB_POLICY_BROAD_GRANT",
            severity="high",
            subtype=subtype,
            title="Broad database privileges reach an application-facing role",
            why_it_matters="Broad grants to anonymous, authenticated, or public roles increase the impact of missing or incorrect row policies.",
            recommendation="Grant only required operations, keep administrative privileges off application roles, and verify RLS denial cases.",
            object_key=object_key,
            statement=statement,
            file=file,
            line=line,
            artifact_scope=artifact_scope,
            extra_evidence=f" principal_class=application_facing principal_count={principal_count}",
        )

    def _finding(
        self,
        *,
        rule_id: str,
        severity: str,
        subtype: str,
        title: str,
        why_it_matters: str,
        recommendation: str,
        object_key: RelationKey,
        file: str | None,
        line: int,
        artifact_scope: str,
        statement: _SqlStatement | None = None,
        statement_ref: str | None = None,
        extra_evidence: str = "",
    ) -> Finding:
        ref = statement.statement_ref if statement is not None else str(statement_ref or "")
        return Finding(
            id=self.ids.next(),
            source="database-policy",
            rule_id=rule_id,
            severity=severity,
            confidence="high",
            title=title,
            evidence=(
                f"detector_subtype={subtype} object_ref={_relation_ref(object_key)} "
                f"statement_ref={ref}{extra_evidence} scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            why_it_matters=why_it_matters,
            recommendation=recommendation,
            file=file,
            line_start=line,
            line_end=line,
            artifact_scope=artifact_scope,
            audit_depth=4,
            inspected_scope="Bounded PostgreSQL SQLGlot AST review plus narrow token parsing for PostgreSQL RLS, policy, and function syntax.",
            not_inspected="This static migration review does not prove the deployed database state, role memberships, ownership, policy composition across other files, or runtime query authorization.",
        )

    def _coverage_finding(
        self,
        reason: str,
        text: str,
        file: str | None,
        artifact_scope: str,
        *,
        reason_count: int = 1,
        reason_set_ref: str | None = None,
    ) -> Finding:
        bounded_sample = f"{text[:4096]}|{text[-4096:]}|chars={len(text)}"
        return Finding(
            id=self.ids.next(),
            source="database-policy",
            rule_id="DB_POLICY_ANALYSIS_INCOMPLETE",
            severity="high",
            confidence="high",
            title="Database policy review scope is incomplete",
            evidence=(
                f"detector_subtype=coverage_incomplete reason={reason} reason_count={reason_count} "
                f"reason_set_ref={reason_set_ref or evidence_hash(reason)} input_ref={evidence_hash(bounded_sample)} "
                f"scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            why_it_matters="Unparsed or unbounded migration content can hide missing RLS, broad grants, or privileged-function weaknesses.",
            recommendation="Reduce the migration to supported bounded statements, correct malformed SQL, and rerun the release review; do not treat this file as passed.",
            file=file,
            artifact_scope=artifact_scope,
            audit_depth=4,
            inspected_scope="The detector identified the exact bounded-analysis failure class without returning SQL content.",
            not_inspected="Statements beyond the reported parser or resource boundary were not trusted as reviewed.",
        )


def _is_sql_file(file: str | None) -> bool:
    return bool(file and PurePosixPath(str(file).replace("\\", "/")).suffix.lower() == ".sql")


def _artifact_scope(file: str | None) -> str:
    path = PurePosixPath(str(file or "").replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if parts & _TEST_PARTS or name.startswith("test_") or ".test." in name or ".spec." in name:
        return "test_fixture"
    if parts & _DOC_PARTS or name.startswith("readme"):
        return "documentation"
    if parts & _MIGRATION_PARTS or "migration" in name:
        return "database_migration"
    return "runtime_source"


def _raw_postgres_context_hint(text: str, file: str | None) -> bool:
    path = PurePosixPath(str(file or "").replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    if parts & _POSTGRES_PATH_PARTS:
        return True
    sample = f"{text[:65536]}\n{text[-65536:]}".lower()
    strong_markers = (
        "row level security",
        "create policy",
        "security definer",
        "auth.uid(",
        "auth.jwt(",
        "service_role",
        "language plpgsql",
        "create extension",
    )
    if any(marker in sample for marker in strong_markers):
        return True
    return bool(parts & _MIGRATION_PARTS and any(marker in sample for marker in (" jsonb", " timestamptz", " serial", " public.")))


def _split_statements(text: str) -> list[_SqlStatement]:
    tokens = Dialect.get_or_raise("postgres").tokenize(text)
    if len(tokens) > MAX_SQL_TOKENS:
        raise _CoverageError("token_limit_exceeded")
    statements: list[_SqlStatement] = []
    current: list[Token] = []
    for token in tokens:
        if token.token_type == TokenType.SEMICOLON:
            if current:
                statements.append(_statement_from_tokens(text, current))
                if len(statements) > MAX_SQL_STATEMENTS:
                    raise _CoverageError("statement_limit_exceeded")
                current = []
            continue
        current.append(token)
    if current:
        statements.append(_statement_from_tokens(text, current))
    if len(statements) > MAX_SQL_STATEMENTS:
        raise _CoverageError("statement_limit_exceeded")
    return statements


def _statement_from_tokens(text: str, tokens: list[Token]) -> _SqlStatement:
    start = tokens[0].start
    end = tokens[-1].end + 1
    return _SqlStatement(text=text[start:end], tokens=tuple(tokens), line=tokens[0].line)


def _words(tokens: tuple[Token, ...]) -> tuple[str, ...]:
    return tuple(str(token.text).strip().upper() for token in tokens)


def _postgres_context(statements: list[_SqlStatement], file: str | None) -> bool:
    path = PurePosixPath(str(file or "").replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    if parts & _POSTGRES_PATH_PARTS:
        return True
    migration_path = bool(parts & _MIGRATION_PARTS or "migration" in path.name.lower())
    for statement in statements:
        words = _words(statement.tokens)
        if _contains_sequence(words, ("ROW", "LEVEL", "SECURITY")):
            return True
        if _contains_sequence(words, ("CREATE", "POLICY")) or _contains_security_definer(words):
            return True
        if any(word in _POSTGRES_TYPE_MARKERS for word in words):
            return True
        if any(word in {"ANON", "AUTHENTICATED", "SERVICE_ROLE"} for word in words):
            return True
        if migration_path and _contains_sequence(words, ("PUBLIC", ".")):
            return True
    return False


def _rls_expected_context(statements: list[_SqlStatement], text: str, file: str | None) -> bool:
    path = PurePosixPath(str(file or "").replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    if "supabase" in parts:
        return True
    sample = f"{text[:65536]}\n{text[-65536:]}".lower()
    if any(marker in sample for marker in ("auth.uid(", "auth.jwt(", "service_role", "create policy", "row level security")):
        return True
    for statement in statements:
        words = _words(statement.tokens)
        if any(word in {"ANON", "AUTHENTICATED", "SERVICE_ROLE"} for word in words):
            return True
    return False


def _is_rls_statement(words: tuple[str, ...]) -> bool:
    return len(words) >= 6 and words[:2] == ("ALTER", "TABLE") and _contains_sequence(words, ("ROW", "LEVEL", "SECURITY"))


def _is_create_policy(words: tuple[str, ...]) -> bool:
    return len(words) >= 2 and words[:2] == ("CREATE", "POLICY")


def _is_create_function(words: tuple[str, ...]) -> bool:
    if len(words) >= 2 and words[:2] == ("CREATE", "FUNCTION"):
        return True
    return len(words) >= 4 and words[:4] == ("CREATE", "OR", "REPLACE", "FUNCTION")


def _is_all_tables_grant(words: tuple[str, ...]) -> bool:
    return bool(words and words[0] == "GRANT" and _contains_sequence(words, ("ON", "ALL", "TABLES", "IN", "SCHEMA")))


def _security_relevant(words: tuple[str, ...]) -> bool:
    if words[:2] == ("CREATE", "TABLE"):
        return True
    if _contains_sequence(words, ("ROW", "LEVEL", "SECURITY")) or _contains_security_definer(words):
        return True
    if _contains_sequence(words, ("CREATE", "POLICY")):
        return True
    return bool(words and words[0] == "GRANT" and any(word in {"ANON", "AUTHENTICATED", "PUBLIC"} for word in words))


def _contains_sequence(words: tuple[str, ...], needle: tuple[str, ...]) -> bool:
    return any(words[index : index + len(needle)] == needle for index in range(len(words) - len(needle) + 1))


def _contains_security_definer(words: tuple[str, ...]) -> bool:
    for index, word in enumerate(words[:-1]):
        if (word == "SECURITY" or word.endswith(" SECURITY")) and words[index + 1] == "DEFINER":
            return True
    return False


def _parse_rls_statement(tokens: tuple[Token, ...]) -> tuple[str, RelationKey, int] | None:
    words = _words(tokens)
    if words[:2] != ("ALTER", "TABLE"):
        return None
    index = 2
    if words[index : index + 2] == ("IF", "EXISTS"):
        index += 2
    if index < len(words) and words[index] == "ONLY":
        index += 1
    parsed = _parse_relation_tokens(tokens, index)
    if parsed is None:
        return None
    table_key, index = parsed
    remainder = words[index:]
    if remainder == ("ENABLE", "ROW", "LEVEL", "SECURITY"):
        return "enable", table_key, tokens[0].line
    if remainder == ("DISABLE", "ROW", "LEVEL", "SECURITY"):
        return "disable", table_key, tokens[0].line
    return None


def _parse_policy_statement(tokens: tuple[Token, ...]) -> tuple[RelationKey, list[tuple[str, int]]] | None:
    words = _words(tokens)
    if words[:2] != ("CREATE", "POLICY") or len(tokens) < 5 or not _identifier_token(tokens[2]):
        return None
    index = 3
    if index >= len(words) or words[index] != "ON":
        return None
    index += 1
    if index < len(words) and words[index] == "TABLE":
        index += 1
    parsed = _parse_relation_tokens(tokens, index)
    if parsed is None:
        return None
    table_key, tail_start = parsed
    tail_words = words[tail_start:]
    if _contains_sequence(tail_words, ("AS", "RESTRICTIVE")):
        return table_key, []

    matches: list[tuple[str, int]] = []
    depth = 0
    index = tail_start
    while index < len(tokens):
        word = words[index]
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and word == "USING":
            clause = _parenthesized_clause(tokens, index + 1)
            if clause is None:
                return None
            inner, close_index = clause
            if _tokens_are_true(inner):
                matches.append(("permissive_using_true", tokens[index].line))
            index = close_index
        elif depth == 0 and word == "WITH" and words[index + 1 : index + 2] == ("CHECK",):
            clause = _parenthesized_clause(tokens, index + 2)
            if clause is None:
                return None
            inner, close_index = clause
            if _tokens_are_true(inner):
                matches.append(("permissive_with_check_true", tokens[index].line))
            index = close_index
        index += 1
    return (table_key, matches) if depth == 0 else None


def _parenthesized_clause(tokens: tuple[Token, ...], index: int) -> tuple[tuple[Token, ...], int] | None:
    if index >= len(tokens) or _words((tokens[index],))[0] != "(":
        return None
    depth = 0
    for cursor in range(index, len(tokens)):
        word = _words((tokens[cursor],))[0]
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
            if depth == 0:
                return tokens[index + 1 : cursor], cursor
    return None


def _tokens_are_true(tokens: tuple[Token, ...]) -> bool:
    reduced = list(tokens)
    while len(reduced) >= 2 and _words((reduced[0], reduced[-1])) == ("(", ")") and _outer_parentheses_cover(reduced):
        reduced = reduced[1:-1]
    return len(reduced) == 1 and _words((reduced[0],))[0] == "TRUE"


def _outer_parentheses_cover(tokens: list[Token]) -> bool:
    depth = 0
    for index, token in enumerate(tokens):
        word = _words((token,))[0]
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
            if depth == 0 and index != len(tokens) - 1:
                return False
        if depth < 0:
            return False
    return depth == 0


def _analyze_security_definer_function(tokens: tuple[Token, ...]) -> tuple[RelationKey, bool, bool, int] | None:
    words = _words(tokens)
    function_index = 1 if words[:2] == ("CREATE", "FUNCTION") else 3 if words[:4] == ("CREATE", "OR", "REPLACE", "FUNCTION") else -1
    if function_index < 0:
        return None
    parsed = _parse_relation_tokens(tokens, function_index + 1)
    if parsed is None:
        return None
    function_key, index = parsed
    if index >= len(tokens) or words[index] != "(":
        return None
    close_index = _matching_parenthesis(tokens, index)
    if close_index is None:
        return None
    header_end = _function_body_index(tokens, close_index + 1)
    header = tokens[:header_end]
    header_words = _words(header)
    security_definer = _contains_security_definer(header_words)
    if security_definer and not any(word == "RETURNS" for word in header_words):
        return None
    fixed_search_path = _has_fixed_search_path(header)
    return function_key, security_definer, fixed_search_path, tokens[0].line


def _function_body_index(tokens: tuple[Token, ...], start: int) -> int:
    for index in range(start, len(tokens) - 1):
        if _words((tokens[index],))[0] == "AS" and "STRING" in tokens[index + 1].token_type.name:
            return index
    return len(tokens)


def _has_fixed_search_path(tokens: tuple[Token, ...]) -> bool:
    words = _words(tokens)
    for index in range(len(tokens) - 2):
        if words[index : index + 2] != ("SET", "SEARCH_PATH"):
            continue
        cursor = index + 2
        if words[cursor] not in {"=", "TO"}:
            continue
        cursor += 1
        if cursor >= len(tokens) or words[cursor] in {"CURRENT", "DEFAULT", "FROM"}:
            continue
        if tokens[cursor].token_type == TokenType.STRING and tokens[cursor].text == "":
            return cursor + 1 == len(tokens) or words[cursor + 1] in _FUNCTION_OPTION_WORDS
        expect_identifier = True
        consumed = False
        while cursor < len(tokens):
            word = words[cursor]
            if expect_identifier:
                if not _identifier_token(tokens[cursor]) or "$" in str(tokens[cursor].text):
                    break
                consumed = True
                expect_identifier = False
                cursor += 1
                continue
            if word == ",":
                expect_identifier = True
                cursor += 1
                continue
            break
        if consumed and not expect_identifier and (cursor == len(tokens) or words[cursor] in _FUNCTION_OPTION_WORDS):
            return True
    return False


def _matching_parenthesis(tokens: tuple[Token, ...], index: int) -> int | None:
    depth = 0
    for cursor in range(index, len(tokens)):
        word = _words((tokens[cursor],))[0]
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
            if depth == 0:
                return cursor
    return None


def _parse_all_tables_grant(tokens: tuple[Token, ...]) -> tuple[RelationKey, set[str], int] | None:
    words = _words(tokens)
    try:
        on_index = words.index("ON")
        to_index = words.index("TO", on_index + 1)
    except ValueError:
        return None
    if words[on_index : on_index + 5] != ("ON", "ALL", "TABLES", "IN", "SCHEMA"):
        return None
    parsed_schema = _parse_identifier_components(tokens, on_index + 5, max_components=1)
    if parsed_schema is None or parsed_schema[1] != to_index:
        return None
    schema_parts, _ = parsed_schema
    object_key: RelationKey = ("", schema_parts[0], "u:*")
    roles, cursor = _parse_role_list(tokens, to_index + 1)
    if roles is None:
        return None
    if cursor < len(words) and words[cursor:] != ("WITH", "GRANT", "OPTION"):
        return None
    return object_key, roles & _TARGET_ROLES, tokens[0].line


def _grant_from_ast(expression: exp.Grant) -> tuple[RelationKey, set[str], str] | None:
    roles: set[str] = set()
    for principal in expression.args.get("principals") or []:
        identifier = principal.args.get("this")
        if isinstance(identifier, exp.Identifier) and not identifier.args.get("quoted"):
            roles.add(str(identifier.this).lower())
    target_roles = roles & _TARGET_ROLES
    if not target_roles:
        return None

    privileges = {
        str(privilege.args.get("this").name).upper()
        for privilege in expression.args.get("privileges") or []
        if privilege.args.get("this") is not None
    }
    grant_option = bool(expression.args.get("grant_option"))
    subtype: str | None = None
    if any(privilege == "ALL" or privilege.startswith("ALL ") for privilege in privileges):
        subtype = "grant_all"
    elif privileges & _ELEVATED_PRIVILEGES:
        subtype = "elevated_table_privilege"
    elif "public" in target_roles and privileges & _WRITE_PRIVILEGES:
        subtype = "public_write_privilege"
    elif len(privileges & _DATA_PRIVILEGES) >= 3 and privileges & _WRITE_PRIVILEGES:
        subtype = "broad_dml_privileges"
    elif grant_option:
        subtype = "grant_option_to_application_role"
    if subtype is None:
        return None

    securable = expression.args.get("securable")
    if isinstance(securable, exp.Table):
        object_key = _table_key_from_ast(securable)
    elif securable is not None:
        object_key = ("u:grant", "u:object", f"h:{evidence_hash(securable.sql(dialect='postgres'))}")
    else:
        object_key = ("u:grant", "u:object", "u:unknown")
    return object_key, target_roles, subtype


def _created_table(expression: exp.Create, statement: _SqlStatement) -> _CreatedTable | None:
    properties = expression.args.get("properties")
    if properties is not None and any(isinstance(item, exp.TemporaryProperty) for item in properties.expressions):
        return None
    target = expression.args.get("this")
    if isinstance(target, exp.Schema):
        target = target.args.get("this")
    if not isinstance(target, exp.Table):
        return None
    identifier = target.args.get("this")
    local_line = int(identifier.meta.get("line") or 1) if isinstance(identifier, exp.Identifier) else 1
    line = statement.line + local_line - 1
    return _CreatedTable(key=_table_key_from_ast(target), line=line, statement_ref=statement.statement_ref)


def _table_key_from_ast(table: exp.Table) -> RelationKey:
    return (
        _ast_identifier_key(table.args.get("catalog"), default=""),
        _ast_identifier_key(table.args.get("db"), default="u:public"),
        _ast_identifier_key(table.args.get("this"), default="u:unknown"),
    )


def _ast_identifier_key(identifier: object, *, default: str) -> str:
    if isinstance(identifier, exp.Identifier):
        prefix = "q" if identifier.args.get("quoted") else "u"
        value = str(identifier.this)
        return f"{prefix}:{value if prefix == 'q' else value.lower()}"
    if identifier is None:
        return default
    return f"u:{str(identifier).lower()}"


def _parse_relation_tokens(tokens: tuple[Token, ...], index: int) -> tuple[RelationKey, int] | None:
    parsed = _parse_identifier_components(tokens, index, max_components=3)
    if parsed is None:
        return None
    components, cursor = parsed
    if len(components) == 1:
        return ("", "u:public", components[0]), cursor
    if len(components) == 2:
        return ("", components[0], components[1]), cursor
    return (components[0], components[1], components[2]), cursor


def _parse_identifier_components(tokens: tuple[Token, ...], index: int, *, max_components: int) -> tuple[list[str], int] | None:
    if index >= len(tokens) or not _identifier_token(tokens[index]):
        return None
    components = [_token_identifier_key(tokens[index])]
    cursor = index + 1
    while cursor + 1 < len(tokens) and _words((tokens[cursor],))[0] == "." and len(components) < max_components:
        if not _identifier_token(tokens[cursor + 1]):
            return None
        components.append(_token_identifier_key(tokens[cursor + 1]))
        cursor += 2
    return components, cursor


def _parse_role_list(tokens: tuple[Token, ...], index: int) -> tuple[set[str] | None, int]:
    roles: set[str] = set()
    cursor = index
    expect_role = True
    while cursor < len(tokens):
        word = _words((tokens[cursor],))[0]
        if expect_role:
            if not _identifier_token(tokens[cursor]):
                return None, cursor
            if tokens[cursor].token_type != TokenType.IDENTIFIER:
                roles.add(str(tokens[cursor].text).lower())
            expect_role = False
            cursor += 1
            continue
        if word != ",":
            break
        expect_role = True
        cursor += 1
    return (roles if roles and not expect_role else None), cursor


def _identifier_token(token: Token) -> bool:
    return token.token_type in {TokenType.IDENTIFIER, TokenType.VAR}


def _token_identifier_key(token: Token) -> str:
    quoted = token.token_type == TokenType.IDENTIFIER
    value = str(token.text)
    return f"{'q' if quoted else 'u'}:{value if quoted else value.lower()}"


def _relation_ref(key: RelationKey) -> str:
    return evidence_hash("|".join(key))


def _is_application_table(key: RelationKey) -> bool:
    schema = key[1].split(":", 1)[-1].lower()
    table = key[2].split(":", 1)[-1].lower()
    if schema in _MANAGED_SCHEMAS or schema.startswith("pg_"):
        return False
    if table in _MIGRATION_TABLES or table.startswith("pg_"):
        return False
    return True
