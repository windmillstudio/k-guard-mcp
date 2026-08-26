from __future__ import annotations

from k_guard_mcp.detectors.database_policy import MAX_SQL_BYTES, MAX_SQL_STATEMENTS, DatabasePolicyDetector
from k_guard_mcp.scanner import KGuardScanner


def _rule_ids(sql: str, file: str = "supabase/migrations/001.sql") -> list[str]:
    return [finding.rule_id for finding in DatabasePolicyDetector().scan_text(sql, file)]


def test_scanner_integrates_database_policy_review_without_touching_non_sql_files() -> None:
    sql = "CREATE TABLE public.profiles (id uuid);"

    sql_result = KGuardScanner().scan_text(sql, "supabase/migrations/001.sql")
    source_result = KGuardScanner().scan_text(sql, "src/schema.ts")

    assert "DB_POLICY_RLS_MISSING" in {finding.rule_id for finding in sql_result.findings}
    assert not any(finding.rule_id.startswith("DB_POLICY_") for finding in source_result.findings)


def test_missing_rls_requires_clear_postgres_or_supabase_context() -> None:
    sql = "CREATE TABLE customers (id integer primary key);"

    assert "DB_POLICY_RLS_MISSING" in _rule_ids(sql)
    assert "DB_POLICY_RLS_MISSING" not in _rule_ids(sql, "db/mysql/schema.sql")
    assert "DB_POLICY_RLS_MISSING" not in _rule_ids(sql, "database/create_postgresql_db.sql")


def test_quoted_table_with_matching_enable_rls_is_not_flagged() -> None:
    sql = '''
    CREATE TABLE "App"."Profiles" ("id" uuid primary key);
    ALTER TABLE IF EXISTS ONLY "App"."Profiles" ENABLE ROW LEVEL SECURITY;
    '''

    assert "DB_POLICY_RLS_MISSING" not in _rule_ids(sql)


def test_created_table_locations_use_file_relative_statement_offsets() -> None:
    sql = "CREATE TABLE public.first_table (id uuid);\n\n\nCREATE TABLE public.second_table (id uuid);"

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/001.sql")
    missing = [finding for finding in findings if finding.rule_id == "DB_POLICY_RLS_MISSING"]

    assert [finding.line_start for finding in missing] == [1, 4]


def test_quoted_identifiers_remain_case_sensitive_for_rls_matching() -> None:
    sql = '''
    CREATE TABLE "App"."Profiles" ("id" uuid primary key);
    ALTER TABLE "App"."profiles" ENABLE ROW LEVEL SECURITY;
    '''

    assert "DB_POLICY_RLS_MISSING" in _rule_ids(sql)


def test_managed_and_temporary_tables_do_not_create_missing_rls_noise() -> None:
    sql = '''
    CREATE TABLE auth.users (id uuid);
    CREATE TABLE supabase_migrations.schema_migrations (version text);
    CREATE TEMP TABLE scratch_rows (id integer);
    '''

    assert "DB_POLICY_RLS_MISSING" not in _rule_ids(sql)


def test_disable_rls_is_critical_and_raw_free() -> None:
    sql = 'ALTER TABLE "Tenant Data"."Customer Records" DISABLE ROW LEVEL SECURITY;'

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/disable.sql")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DB_POLICY_RLS_DISABLED"
    assert finding.severity == "critical"
    assert finding.artifact_scope == "database_migration"
    assert "Tenant Data" not in finding.evidence
    assert "Customer Records" not in finding.evidence
    assert "object_ref=" in finding.evidence
    assert "statement_ref=" in finding.evidence
    assert "raw_returned=false" in finding.evidence


def test_ast_grant_detects_all_and_broad_dml_but_not_narrow_select() -> None:
    all_sql = "GRANT ALL PRIVILEGES ON TABLE public.profiles TO anon;"
    broad_sql = "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.profiles TO authenticated;"
    narrow_sql = "GRANT SELECT ON TABLE public.profiles TO authenticated;"

    assert "DB_POLICY_BROAD_GRANT" in _rule_ids(all_sql, "db/schema.sql")
    assert "DB_POLICY_BROAD_GRANT" in _rule_ids(broad_sql, "db/schema.sql")
    assert "DB_POLICY_BROAD_GRANT" not in _rule_ids(narrow_sql, "db/schema.sql")


def test_grant_scope_rejects_non_target_and_quoted_public_roles() -> None:
    admin_sql = "GRANT ALL ON TABLE public.profiles TO app_admin;"
    quoted_role_sql = 'GRANT ALL ON TABLE public.profiles TO "public";'

    assert "DB_POLICY_BROAD_GRANT" not in _rule_ids(admin_sql, "db/schema.sql")
    assert "DB_POLICY_BROAD_GRANT" not in _rule_ids(quoted_role_sql, "db/schema.sql")


def test_narrow_postgres_all_tables_command_is_detected() -> None:
    sql = "GRANT SELECT ON ALL TABLES IN SCHEMA public TO PUBLIC;"

    findings = DatabasePolicyDetector().scan_text(sql, "postgres/migrations/grants.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_BROAD_GRANT"]
    assert "detector_subtype=all_tables_in_schema" in findings[0].evidence


def test_default_permissive_true_using_and_check_are_detected() -> None:
    sql = 'CREATE POLICY "open policy" ON "App"."Profiles" USING ((true)) WITH CHECK (true);'

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/policy.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_PERMISSIVE_TRUE", "DB_POLICY_PERMISSIVE_TRUE"]
    evidence = {finding.evidence for finding in findings}
    assert any("permissive_using_true" in item for item in evidence)
    assert any("permissive_with_check_true" in item for item in evidence)
    assert all("open policy" not in item and "Profiles" not in item for item in evidence)


def test_restrictive_or_identity_bound_policy_is_not_flagged() -> None:
    restrictive = "CREATE POLICY p ON public.profiles AS RESTRICTIVE USING (true);"
    identity_bound = "CREATE POLICY p ON public.profiles USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());"

    assert "DB_POLICY_PERMISSIVE_TRUE" not in _rule_ids(restrictive)
    assert "DB_POLICY_PERMISSIVE_TRUE" not in _rule_ids(identity_bound)


def test_security_definer_requires_function_local_literal_search_path() -> None:
    missing = '''
    CREATE OR REPLACE FUNCTION public.lookup_profile() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$ BEGIN RETURN; END $$;
    '''
    fixed = '''
    CREATE OR REPLACE FUNCTION public.lookup_profile() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
    AS $$ BEGIN RETURN; END $$;
    '''
    empty = "CREATE FUNCTION public.lookup_profile() RETURNS void SECURITY DEFINER SET search_path = '' LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;"

    assert "DB_POLICY_SECURITY_DEFINER_SEARCH_PATH" in _rule_ids(missing, "postgres/functions.sql")
    assert "DB_POLICY_SECURITY_DEFINER_SEARCH_PATH" not in _rule_ids(fixed, "postgres/functions.sql")
    assert "DB_POLICY_SECURITY_DEFINER_SEARCH_PATH" not in _rule_ids(empty, "postgres/functions.sql")


def test_search_path_text_inside_function_body_does_not_suppress_finding() -> None:
    sql = '''
    CREATE FUNCTION public.lookup_profile() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$ BEGIN RAISE NOTICE 'SET search_path = pg_catalog'; RETURN; END $$;
    '''

    assert "DB_POLICY_SECURITY_DEFINER_SEARCH_PATH" in _rule_ids(sql, "postgres/functions.sql")


def test_dynamic_or_user_search_path_is_not_treated_as_fixed() -> None:
    sql = '''
    CREATE FUNCTION public.lookup_profile() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
    AS $$ BEGIN RETURN; END $$;
    '''

    assert "DB_POLICY_SECURITY_DEFINER_SEARCH_PATH" in _rule_ids(sql, "postgres/functions.sql")


def test_malformed_postgres_sql_fails_closed_without_returning_raw_sql() -> None:
    sql = "CREATE TABLE public.customer_secrets (id uuid,"

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/broken.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_ANALYSIS_INCOMPLETE"]
    assert findings[0].severity == "high"
    assert "customer_secrets" not in findings[0].evidence
    assert "reason=statement_parse_error" in findings[0].evidence
    assert "raw_returned=false" in findings[0].evidence
    assert DatabasePolicyDetector().scan_text(sql, "db/mysql/schema.sql") == []


def test_malformed_policy_command_fails_closed() -> None:
    sql = "CREATE POLICY p ON public.profiles USING ("

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/broken_policy.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_ANALYSIS_INCOMPLETE"]
    assert "reason=policy_syntax_unresolved" in findings[0].evidence


def test_oversized_postgres_input_fails_closed_at_the_bound() -> None:
    sql = "-- supabase\n" + (" " * MAX_SQL_BYTES) + "CREATE TABLE public.profiles(id uuid);"

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/oversized.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_ANALYSIS_INCOMPLETE"]
    assert "reason=input_byte_limit_exceeded" in findings[0].evidence


def test_statement_count_limit_fails_closed_with_a_precise_reason() -> None:
    sql = ";".join("SELECT 1" for _ in range(MAX_SQL_STATEMENTS + 1))

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/many.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_ANALYSIS_INCOMPLETE"]
    assert "reason=statement_limit_exceeded" in findings[0].evidence


def test_unsupported_postgres_create_table_form_is_not_silently_passed() -> None:
    sql = "CREATE TABLE public.typed_profiles OF public.profile_type;"

    findings = DatabasePolicyDetector().scan_text(sql, "supabase/migrations/typed.sql")

    assert [finding.rule_id for finding in findings] == ["DB_POLICY_ANALYSIS_INCOMPLETE"]
    assert "reason=security_statement_unsupported" in findings[0].evidence


def test_sqlglot_command_fallback_does_not_log_raw_sql(caplog) -> None:
    sql = "DO $$ BEGIN CREATE TYPE private_marker AS ENUM ('one', 'two'); END $$;"

    DatabasePolicyDetector().scan_text(sql, "db/drizzle/typed.sql")

    assert "private_marker" not in caplog.text


def test_database_policy_findings_distinguish_migrations_tests_and_docs() -> None:
    sql = "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;"
    detector = DatabasePolicyDetector()

    migration = detector.scan_text(sql, "supabase/migrations/001.sql")[0]
    fixture = detector.scan_text(sql, "tests/fixtures/unsafe.sql")[0]
    documentation = detector.scan_text(sql, "docs/examples/unsafe.sql")[0]

    assert migration.artifact_scope == "database_migration"
    assert fixture.artifact_scope == "test_fixture"
    assert documentation.artifact_scope == "documentation"
