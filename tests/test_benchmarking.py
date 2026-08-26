import contextlib
import csv
import hashlib
import io
import json
import tempfile
import threading
import zipfile
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from k_guard_mcp import cli
from k_guard_mcp.benchmarking import run_field_benchmark, write_benchmark_template
from k_guard_mcp.guardian import run_guardian_audit, write_guardian_manifest_template, write_guardian_report
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.suppression import (
    SUPPRESSION_FIELDS,
    _guardian_row_suppression_binding,
    finding_fingerprint as suppression_fingerprint,
)
from scripts.build_top_domain_manifest import build_manifest_rows
from scripts.deep_probe_synthetic_calibration import SCENARIOS, run_synthetic_deep_probe_calibration, to_markdown as deep_probe_to_markdown
from scripts.inner_core_product_gate import run_inner_core_product_gate, to_markdown as inner_core_to_markdown
from scripts.passive_calibration_summary import summarize_reports, to_markdown
from scripts.passive_homepage_calibration import (
    _domain_role,
    _finding_evidence_items,
    _homepage_candidate_urls,
    main as passive_homepage_main,
    _redirect_scope,
    _registrable_domain_approx,
    run_passive_homepage_calibration,
)


def _write_bound_suppressions(
    path: Path,
    guardian_row: dict,
    findings: list[dict],
    *,
    expires: str = "2099-01-01",
    fingerprint_override: str = "",
) -> None:
    binding = _guardian_row_suppression_binding(guardian_row)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUPPRESSION_FIELDS)
        writer.writeheader()
        for finding in findings:
            bound = {
                **finding,
                **binding,
                "target_id": guardian_row.get("target_id", ""),
            }
            writer.writerow(
                {
                    **binding,
                    "target_id": guardian_row.get("target_id", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "finding_fingerprint": fingerprint_override or suppression_fingerprint(bound),
                    "owner": "team",
                    "reason": "documented bounded fixture decision",
                    "expires": expires,
                }
            )


def test_field_benchmark_aggregates_cohorts_manual_fp_and_strong_identifiers():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_report(root / "general.json", [])
        _write_report(
            root / "vibe.json",
            [
                {
                    "rule_id": "DYN_RESPONSE_PII_LEAK",
                    "severity": "high",
                    "evidence": "Strong identifier tier detected: BANK_ACCOUNT=1, RRN=1",
                },
                {"rule_id": "DYN_SECURITY_HEADERS_MISSING", "severity": "medium", "evidence": "Missing headers: content-security-policy"},
            ],
        )
        _write_report(root / "authorized.json", [{"rule_id": "DYN_RESPONSE_SECRET_LEAK", "severity": "critical", "evidence": "secret-like data"}])
        manifest = root / "manifest.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,cohort,url,mode,authorized,authorization_note,deep_active,report_path,manual_verdict,notes",
                    "general-01,general,https://general.example,report,false,,,general.json,needs_review,quiet baseline",
                    "vibe-01,vibecoded_suspected,https://vibe.example,report,false,,,vibe.json,needs_review,strong signal",
                    "auth-01,authorized_owned_partner,https://owned.example,report,true,owned staging,,authorized.json,needs_review,partner",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        review = root / "review.csv"
        review.write_text(
            "\n".join(
                [
                    "target_id,rule_id,verdict,notes",
                    "vibe-01,DYN_RESPONSE_PII_LEAK,true_positive,confirmed",
                    "auth-01,DYN_RESPONSE_SECRET_LEAK,false_positive,test token",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        report = run_field_benchmark(manifest, review_path=review)

    by_cohort = report["aggregate"]["by_cohort"]
    assert by_cohort["general"]["high_critical_target_rate"] == 0
    assert by_cohort["vibecoded_suspected"]["high_critical_target_rate"] == 1
    assert by_cohort["vibecoded_suspected"]["strong_identifier_target_rate"] == 1
    assert by_cohort["authorized_owned_partner"]["manual_false_positive_rate"] == 1
    assert report["rows"][1]["strong_identifier_detected"] is True


def test_benchmark_template_creates_20_20_10_slots():
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "targets.csv"
        write_benchmark_template(output)
        lines = output.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 51
    assert sum(1 for line in lines if line.startswith("general-")) == 20
    assert sum(1 for line in lines if line.startswith("vibe-")) == 20
    assert sum(1 for line in lines if line.startswith("auth-")) == 10


def test_benchmark_probe_rows_do_not_run_without_explicit_flag():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "manifest.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,cohort,url,mode,authorized,authorization_note,deep_active,report_path,manual_verdict,notes",
                    "vibe-01,vibecoded_suspected,https://vibe.example,probe,true,owned,false,,needs_review,should not run",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report = run_field_benchmark(manifest, run_probes=False)

    assert report["rows"][0]["status"] == "skipped_probe_requires_flag"
    assert report["aggregate"]["by_cohort"]["vibecoded_suspected"]["measured_count"] == 0


def test_guardian_template_and_drift_report_include_fix_plan_without_probes():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "route.py").write_text("def handler(request):\n    email = request.json['email']\n    print(email)\n    return {'email': email}\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        write_guardian_manifest_template(root / "template.csv")
        manifest.write_text(
            "\n".join(
                [
                    "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes",
                    f"workspace-01,workspace,{workspace},true,local project,false,,true,high,team,workspace scan",
                    "http-01,http,http://127.0.0.1:1,true,local test,true,,false,high,team,probe disabled by default",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        previous = root / "previous.json"
        previous.write_text(
            json.dumps(
                {
                    "targets": [
                        {
                            "target_id": "workspace-01",
                            "fail_on": "high",
                            "findings": [
                                {
                                    "rule_id": "AST_TAINT_PII_TO_LOG",
                                    "source": "ast-taint",
                                    "severity": "high",
                                    "file": str(workspace / "route.py"),
                                    "line_start": 3,
                                }
                            ],
                        }
                    ]
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest, previous_report_path=previous, run_probes=False)
        output = root / "guardian.json"
        markdown = root / "guardian.md"
        html = root / "guardian.html"
        write_guardian_report(report, output, markdown_path=markdown, html_path=html)
        template_exists = (root / "template.csv").exists()
        markdown_payload = markdown.read_text(encoding="utf-8")
        html_payload = html.read_text(encoding="utf-8")

    assert template_exists
    assert report["raw_free"] is True
    assert report["summary"]["target_count"] == 2
    assert report["summary"]["blocking_target_count"] >= 1
    assert any(item["rule_id"] == "AST_TAINT_PII_TO_LOG" for item in report["fix_plan"])
    assert report["targets"][1]["status"] == "skipped_probe_requires_run_probes"
    assert report["baseline"]["status"] == "comparison_loaded"
    assert report["drift"]["comparison_available"] is True
    assert report["drift"]["previous_loaded"] is True
    assert report["experience"]["persona"] == "안경선배"
    assert report["experience"]["verdict_code"] == "review_only"
    assert "안경선배 Guardian Report" in markdown_payload
    assert "안경선배 Guardian Report" in html_payload
    assert "execution_mode" in markdown_payload
    assert "Execution Contract" in html_payload


def test_guardian_scope_assertion_requires_explicit_scope_proof_ref():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "health.ts").write_text("export const ok = true\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,notes",
                    f"workspace-01,workspace,{workspace},true,local project,false,,true,high,team,pre-release audit,runtime_config,owned users,,local_workspace,,workspace scan",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest, run_probes=False, fail_on_override="high")

    assert report["intent_contract"]["business_purpose_complete"] is True
    assert report["intent_contract"]["scope_assertion_complete"] is False
    assert report["targets"][0]["scope_contract"]["legacy_authorization_note_present"] is True
    assert report["targets"][0]["scope_contract"]["assertion_present"] is False


def test_guardian_manifest_metadata_is_raw_free():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "health.ts").write_text("export const ok = true\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,notes",
                    f"홍길동,workspace,{workspace},true,홍길동 900101-1234567,false,,true,high,홍길동,출하 전 점검,personal_data,홍길동 사용자,,local_workspace,홍길동 승인 문서,raw-free check",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest, run_probes=False, fail_on_override="high")

    payload = json.dumps(report, ensure_ascii=False)
    assert "홍길동" not in payload
    assert "900101-1234567" not in payload
    assert report["targets"][0]["target_id"].startswith("target_id:")
    assert report["targets"][0]["owner"].startswith("owner:")
    assert report["targets"][0]["authorization"]["note_present"] is True
    assert report["targets"][0]["scope_contract"]["assertion_present"] is True


def test_korean_senior_guardian_profile_fails_closed_when_dynamic_domains_are_missing():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "primary-app,app,workspace,app,true,local workspace,false,,true,high,team,pre-release web app review,personal_data,owned test users,,local_workspace,repo assertion,korean_senior,strict review\n",
            encoding="utf-8",
        )
        output = root / "guardian.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["guardian", "--manifest", str(manifest), "--output", str(output), "--fail-on", "high"])
        report = json.loads(output.read_text(encoding="utf-8"))

    assert code == 3
    assert report["summary"]["blocking_target_count"] == 1
    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["review_contract_passed"] is False
    assert set(report["review_contract"]["missing_review_domains"]) == {"site_security", "api_exposure"}


def test_korean_senior_guardian_profile_rejects_unreachable_http_execution():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "primary-app,app,workspace,app,true,local workspace,false,,true,high,team,pre-release review,personal_data,owned users,,local_workspace,repo assertion,korean_senior,strict\n"
            "primary-app,web,http,http://127.0.0.1:1,true,local server,true,,,high,team,runtime review,runtime_response,owned users,/|/api,local_http,local server assertion,korean_senior,strict\n",
            encoding="utf-8",
        )
        output = root / "guardian.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["guardian", "--manifest", str(manifest), "--run-probes", "--output", str(output), "--fail-on", "high"])
        report = json.loads(output.read_text(encoding="utf-8"))

    assert code == 3
    assert report["summary"]["blocking_target_count"] == 2
    assert report["review_contract"]["http_attempted_count"] == 1
    assert report["review_contract"]["http_failed_execution_count"] == 1
    assert report["guardian_gate"]["review_contract_passed"] is False


def test_korean_senior_guardian_profile_covers_all_four_domains_and_passes(monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "test-guardian-release-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    class SeniorProfileHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            SeniorProfileHandler.calls.append((self.path, bool(self.headers.get("Cookie"))))
            if self.path == "/v1/orders" and not self.headers.get("Cookie"):
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
        SeniorProfileHandler.calls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), SeniorProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            identity_body = b"<html><body>ok</body></html>"
            (root / "session.json").write_text(
                json.dumps(
                    {
                        "origin": origin,
                        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
                        "headers": {"Cookie": "session=local-test"},
                        "identity_assertion": {
                            "path": "/v1/orders",
                            "expected_status": 200,
                            "expected_body_sha256": hashlib.sha256(identity_body).hexdigest(),
                        },
                    }
                ),
                encoding="utf-8",
            )
            manifest = root / "guardian.csv"
            manifest.write_text(
                "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
                "primary-app,app,workspace,app,true,local workspace,false,,true,high,team,pre-release web app review,personal_data|runtime_config,owned test users,,local_workspace,repo assertion,korean_senior,strict review\n"
                f"primary-app,web,http,{origin},true,local server,true,session.json,,high,team,runtime web and API review,runtime_response|personal_data,owned test users,/|/api|/api/users|/v1/orders,local_http,local server assertion,korean_senior,strict review\n",
                encoding="utf-8",
            )
            output = root / "guardian.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(
                    [
                        "guardian",
                        "--manifest",
                        str(manifest),
                        "--run-probes",
                        "--output",
                        str(output),
                        "--fail-on",
                        "high",
                    ]
                )
            report = json.loads(output.read_text(encoding="utf-8"))
        finally:
            server.shutdown()
            thread.join(timeout=5)

    assert code == 3
    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["review_contract_passed"] is True
    assert report["guardian_gate"]["release_qualification_passed"] is False
    assert report["experience"]["verdict_code"] == "hold_qualification"
    assert report["review_contract"]["profile"] == "korean_senior"
    assert report["review_contract"]["coverage_grade"] == "korean_senior_gate_ready"
    assert all(domain["passed"] for domain in report["review_contract"]["domains"].values())
    assert report["targets"][0]["review_evidence"]["review_coverage"]["source_kind"] == "workspace"
    assert report["targets"][1]["review_evidence"]["review_coverage"]["source_kind"] == "http"
    assert ("/v1/orders", False) in SeniorProfileHandler.calls
    assert ("/v1/orders", True) in SeniorProfileHandler.calls
    assert report["targets"][1]["review_evidence"]["dynamic_probe_contract"]["authenticated_comparison"] is True


def test_korean_senior_guardian_rejects_empty_workspace_even_with_live_http():
    class OkHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), OkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty-app").mkdir()
            manifest = root / "guardian.csv"
            manifest.write_text(
                "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
                "primary-app,app,workspace,empty-app,true,local,false,,true,high,team,release review,personal_data,owned users,,local_workspace,assertion,korean_senior,empty\n"
                f"primary-app,web,http,http://127.0.0.1:{server.server_port},true,local,true,,false,high,team,runtime review,runtime_response,owned users,/,local_http,assertion,korean_senior,http\n",
                encoding="utf-8",
            )
            report = run_guardian_audit(manifest, run_probes=True, fail_on_override="high")
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert report["review_contract"]["passed"] is False
    assert report["review_contract"]["workspace_empty_or_unsupported_count"] == 1
    assert report["review_contract"]["workspace_review_count"] == 0


def test_korean_senior_guardian_requires_a_readable_production_source():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "app.py").write_bytes(b"def app():\x00\n")
        (workspace / "README.md").write_text("readable documentation\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "primary-app,app,workspace,app,true,local,false,,true,high,team,release review,personal_data,owned users,,local_workspace,assertion,korean_senior,unreadable source\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest, fail_on_override="high")

    inventory = report["targets"][0]["review_evidence"]["review_coverage"]["inventory"]
    assert inventory["production_source_file_count"] == 1
    assert inventory["scanned_production_source_file_count"] == 0
    assert report["review_contract"]["workspace_attempted_count"] == 1
    assert report["review_contract"]["workspace_review_count"] == 0


def test_korean_senior_guardian_rejects_empty_or_docstring_only_source():
    reports = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "primary-app,app,workspace,app,true,local,false,,true,high,team,release review,personal_data,owned users,,local_workspace,assertion,korean_senior,empty source\n",
            encoding="utf-8",
        )
        source = workspace / "app.py"
        for content in ("", '"""documentation only"""\n', "# comment only\n", "pass\n", "def app():\n    pass\n"):
            source.write_text(content, encoding="utf-8")
            reports.append(run_guardian_audit(manifest, fail_on_override="high"))

    for report in reports:
        inventory = report["targets"][0]["review_evidence"]["review_coverage"]["inventory"]
        assert inventory["scanned_production_source_file_count"] == 1
        assert inventory["substantive_production_source_file_count"] == 0
        assert report["review_contract"]["workspace_review_count"] == 0


def test_guardian_fails_closed_when_workspace_changes_during_audit():
    class MutatingScanner(KGuardScanner):
        def scan_workspace(self, path, include_flow=True):
            result = super().scan_workspace(path, include_flow=include_flow)
            (Path(path) / "app.py").write_text("print('changed during audit')\n", encoding="utf-8")
            return result

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "app.py").write_text("print('initial')\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "primary-app,app,workspace,app,true,local,false,,true,high,team,release review,personal_data,owned users,,local_workspace,assertion,korean_senior,mutation test\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest, scanner=MutatingScanner(), fail_on_override="high")

    target = report["targets"][0]
    assert target["review_evidence"]["source_tree_consistency"]["matched"] is False
    assert "GUARDIAN_SOURCE_CHANGED_DURING_AUDIT" in target["rule_ids"]
    assert target["gate"]["passed"] is False
    assert report["review_contract"]["workspace_review_count"] == 0


def test_korean_senior_guardian_rejects_http_scope_that_only_returns_404():
    class MissingHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(404)
            self.end_headers()

        def do_OPTIONS(self):
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), MissingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "app"
            workspace.mkdir()
            (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
            manifest = root / "guardian.csv"
            manifest.write_text(
                "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
                "primary-app,app,workspace,app,true,local,false,,true,high,team,release review,personal_data,owned users,,local_workspace,assertion,korean_senior,workspace\n"
                f"primary-app,web,http,http://127.0.0.1:{server.server_port},true,local,true,,false,high,team,runtime review,runtime_response,owned users,/|/api,local_http,assertion,korean_senior,http\n",
                encoding="utf-8",
            )
            report = run_guardian_audit(manifest, run_probes=True, fail_on_override="high")
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert report["review_contract"]["passed"] is False
    assert report["review_contract"]["http_failed_execution_count"] == 1
    assert report["targets"][1]["review_evidence"]["dynamic_probe_contract"]["required_path_reached_count"] == 0


def test_guardian_imports_only_hashed_raw_free_finding_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        imported = root / "imported.json"
        imported.write_text(
            json.dumps(
                {
                    "raw_free": True,
                    "metadata": {"patient_note": "private-patient-note-773"},
                    "findings": [
                        {
                            "rule_id": "IMPORTED_TEST_RULE",
                            "source": "fixture",
                            "severity": "high",
                            "title": "private-title-773",
                            "evidence": "private-evidence-773",
                            "metadata": {"note": "private-metadata-773"},
                            "method": "private-method-773",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        manifest = root / "guardian.csv"
        manifest.write_text(
            "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "report,report,imported.json,true,local,false,,false,high,team,aggregate raw-free evidence,raw_free_findings,report scope,,raw_free_report_import,assertion,korean_senior,import\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest)
        payload = json.dumps(report, ensure_ascii=False)
        imported.write_text(json.dumps({"raw_free": False, "findings": []}), encoding="utf-8")
        rejected = run_guardian_audit(manifest)

    assert report["targets"][0]["findings"][0]["rule_id"] == "IMPORTED_TEST_RULE"
    for raw in ("private-patient-note-773", "private-title-773", "private-evidence-773", "private-metadata-773", "private-method-773"):
        assert raw not in payload
    assert report["targets"][0]["review_evidence"]["import_contract"]["raw_metadata_returned"] is False
    assert rejected["targets"][0]["status"] == "error"
    assert "GUARDIAN_TARGET_FAILED" in rejected["targets"][0]["rule_ids"]


def test_guardian_config_findings_do_not_return_arbitrary_source_text():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "server.ts").write_text(
            'cors({ origin: "*" }) // INTERNAL-CODENAME-ORCHID\n',
            encoding="utf-8",
        )
        manifest = root / "guardian.csv"
        manifest.write_text(
            "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
            "app,workspace,app,true,local,false,,true,high,team,review,runtime_config,owned users,,local_workspace,assertion,standard,test\n",
            encoding="utf-8",
        )
        report = run_guardian_audit(manifest)
    payload = json.dumps(report, ensure_ascii=False)
    assert "CONFIG_CORS_WILDCARD" in report["targets"][0]["rule_ids"]
    assert "INTERNAL-CODENAME-ORCHID" not in payload


def test_cli_benchmark_writes_json_markdown_and_html():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report_path = root / "report.json"
        _write_report(report_path, [{"rule_id": "DYN_RESPONSE_PII_LEAK", "severity": "high", "evidence": "Bulk record tier detected in response: EMAIL=4, PERSON=4"}])
        manifest = root / "manifest.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,cohort,url,mode,authorized,authorization_note,deep_active,report_path,manual_verdict,notes",
                    "vibe-01,vibecoded_suspected,https://vibe.example,report,false,,,report.json,needs_review,bulk",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        output = root / "benchmark.json"
        markdown = root / "benchmark.md"
        html = root / "benchmark.html"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli.main(["benchmark", "--manifest", str(manifest), "--output", str(output), "--markdown", str(markdown), "--html", str(html)])

        data = json.loads(output.read_text(encoding="utf-8"))
        markdown_payload = markdown.read_text(encoding="utf-8")
        html_payload = html.read_text(encoding="utf-8")

    assert code == 0
    assert data["rows"][0]["high_or_critical"] is True
    assert "K-Guard Field Benchmark" in markdown_payload
    assert "K-Guard Field Benchmark" in html_payload


def test_field_benchmark_authorization_note_is_raw_free():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report_path = root / "report.json"
        _write_report(report_path, [])
        manifest = root / "manifest.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,cohort,url,mode,authorized,authorization_note,deep_active,report_path,manual_verdict,notes",
                    "auth-01,authorized_owned_partner,https://example.com,report,true,partner scope memo AliceSmith 홍길동 sk-thisisaverylongfakeapikey888,false,report.json,needs_review,release note mentions AliceSmith 홍길동",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report = run_field_benchmark(manifest)

    payload = json.dumps(report, ensure_ascii=False)
    assert "partner scope memo" not in payload
    assert "release note mentions" not in payload
    assert "AliceSmith" not in payload
    assert "홍길동" not in payload
    assert "sk-thisisaverylongfakeapikey888" not in payload
    assert report["rows"][0]["authorization"]["note_present"] is True
    assert report["rows"][0]["authorization"]["note_ref"]["raw_returned"] is False
    assert report["rows"][0]["notes"]["present"] is True
    assert report["rows"][0]["notes"]["raw_returned"] is False


def test_cli_guardian_fail_on_turns_blocking_report_into_exit_code():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "app"
        workspace.mkdir()
        (workspace / "route.py").write_text("def handler(request):\n    email = request.json['email']\n    print(email)\n    return {'email': email}\n", encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes",
                    f"workspace-01,workspace,{workspace},true,local project,false,,true,high,team,workspace scan",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report_mode_output = root / "guardian-report.json"
        gate_output = root / "guardian-gate.json"
        stdout_report = io.StringIO()
        with contextlib.redirect_stdout(stdout_report):
            report_code = cli.main(["guardian", "--manifest", str(manifest), "--output", str(report_mode_output)])
        stdout_gate = io.StringIO()
        with contextlib.redirect_stdout(stdout_gate):
            gate_code = cli.main(["guardian", "--manifest", str(manifest), "--output", str(gate_output), "--fail-on", "high"])

        report_payload = json.loads(report_mode_output.read_text(encoding="utf-8"))
        gate_payload = json.loads(gate_output.read_text(encoding="utf-8"))
        gate_stdout = json.loads(stdout_gate.getvalue())

    assert report_code == 0
    assert report_payload["summary"]["blocking_target_count"] >= 1
    assert report_payload["baseline"]["status"] == "initial_snapshot"
    assert report_payload["drift"]["new_blocking_finding_count"] == 0
    assert "guardian_gate" not in report_payload
    assert gate_code == 3
    assert gate_payload["baseline"]["status"] == "initial_snapshot"
    assert gate_payload["drift"]["new_blocking_finding_count"] == 0
    assert gate_payload["guardian_gate"]["passed"] is False
    assert gate_payload["guardian_gate"]["fail_on"] == "high"
    assert gate_stdout["guardian_gate"]["blocking_target_count"] >= 1
    assert gate_stdout["guardian_gate"]["new_blocking_finding_count"] == 0


def test_guardian_suppression_policy_is_fingerprint_bound_and_fail_closed(monkeypatch):
    monkeypatch.delenv("K_GUARD_SEMGREP_EXECUTABLE", raising=False)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app = root / "app"
        route = app / "app" / "api" / "users" / "[id]" / "route.ts"
        route.parent.mkdir(parents=True)
        route.write_text(
            "import { NextResponse } from 'next/server'\n"
            "export async function GET(request: Request, { params }) {\n"
            "  const user = await prisma.user.findUnique({ where: { id: params.id } })\n"
            "  return NextResponse.json(user)\n"
            "}\n",
            encoding="utf-8",
        )
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,audit_profile,notes\n"
            f"test-app,app,workspace,{app},true,local,false,,true,high,team,korean_senior,next route\n",
            encoding="utf-8",
        )
        first_output = root / "guardian-first.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(first_output), "--fail-on", "high"]) == 3
        first = json.loads(first_output.read_text(encoding="utf-8"))
        high_finding = next(item for item in first["targets"][0]["findings"] if item["rule_id"] == "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK")
        suppressions = root / "suppressions.csv"
        _write_bound_suppressions(suppressions, first["targets"][0], [high_finding])
        suppressed_output = root / "guardian-suppressed.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(suppressed_output), "--fail-on", "high", "--suppressions", str(suppressions)]) == 3
        suppressed = json.loads(suppressed_output.read_text(encoding="utf-8"))
        assert suppressed["guardian_gate"]["passed"] is False
        assert suppressed["targets"][0]["gate"]["passed"] is False
        assert {"DEEP_ANALYSIS_COVERAGE_INCOMPLETE", "SCA_COVERAGE_INCOMPLETE"}.issubset(
            {finding["rule_id"] for finding in suppressed["targets"][0]["findings"]}
        )
        assert suppressed["experience"]["verdict_code"] == "hold_coverage"
        assert suppressed["suppression_policy"]["suppressed_count"] == 1

        bad_suppressions = root / "bad-suppressions.csv"
        _write_bound_suppressions(
            bad_suppressions,
            first["targets"][0],
            [high_finding],
            expires="2000-01-01",
        )
        bad_output = root / "guardian-bad-suppression.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(bad_output), "--fail-on", "high", "--suppressions", str(bad_suppressions)]) == 3
        bad = json.loads(bad_output.read_text(encoding="utf-8"))
        assert bad["guardian_gate"]["passed"] is False
        assert bad["suppression_policy"]["invalid_count"] == 1
        assert "SUPPRESSION_POLICY_ROW_INVALID" in {finding["rule_id"] for finding in bad["findings"]}


def test_guardian_suppression_cannot_clear_coverage_gaps():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,audit_profile,notes\n"
            "test-app,web,http,http://127.0.0.1:1,true,local,false,,false,high,team,korean_senior,http gap\n",
            encoding="utf-8",
        )
        first_output = root / "guardian-first.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(first_output), "--fail-on", "high"]) == 3
        first = json.loads(first_output.read_text(encoding="utf-8"))
        gap_finding = first["targets"][0]["findings"][0]
        suppressions = root / "suppressions.csv"
        _write_bound_suppressions(suppressions, first["targets"][0], [gap_finding])
        suppressed_output = root / "guardian-suppressed.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(suppressed_output), "--fail-on", "high", "--suppressions", str(suppressions)]) == 3
        suppressed = json.loads(suppressed_output.read_text(encoding="utf-8"))
        assert suppressed["guardian_gate"]["passed"] is False
        assert suppressed["summary"]["coverage_gap_target_count"] == 1
        assert suppressed["suppression_policy"]["invalid_count"] == 1
        assert suppressed["execution_contract"]["suppression_policy"] == "applied_fail_closed"
        assert "SUPPRESSION_POLICY_UNSUPPRESSIBLE_RULE" in {finding["rule_id"] for finding in suppressed["findings"]}


def test_guardian_suppression_cannot_clear_mcp_control_failures_from_imported_reports():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        imported_report = root / "mcp-report.json"
        imported_findings = [
            {
                "id": f"mcp-control-{index}",
                "source": "mcp",
                "rule_id": rule_id,
                "severity": "info",
                "confidence": "high",
                "title": rule_id,
                "evidence": f"control_{index}=blocked raw_returned=false",
                "why_it_matters": "MCP control failure must remain visible in release evidence.",
                "recommendation": "Fix the MCP control failure before release.",
            }
            for index, rule_id in enumerate(
                [
                    "MCP_TEXT_INPUT_BUDGET_EXCEEDED",
                    "MCP_SESSION_PROBE_DISABLED_BY_DEFAULT",
                    "MCP_EXTERNAL_PROBE_AUTHORIZATION_REQUIRED",
                ],
                start=1,
            )
        ]
        imported_report.write_text(json.dumps({"raw_free": True, "findings": imported_findings}, ensure_ascii=False), encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,audit_profile,notes\n"
            f"test-app,mcp-report,report,{imported_report},true,local,false,,false,info,team,korean_senior,mcp control import\n",
            encoding="utf-8",
        )
        first_output = root / "guardian-first.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(first_output), "--fail-on", "info"]) == 3
        first = json.loads(first_output.read_text(encoding="utf-8"))
        suppressions = root / "suppressions.csv"
        _write_bound_suppressions(
            suppressions,
            first["targets"][0],
            first["targets"][0]["findings"],
        )
        suppressed_output = root / "guardian-suppressed-mcp-controls.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--output", str(suppressed_output), "--fail-on", "info", "--suppressions", str(suppressions)]) == 3
        suppressed = json.loads(suppressed_output.read_text(encoding="utf-8"))
        assert suppressed["guardian_gate"]["passed"] is False
        assert suppressed["targets"][0]["gate"]["passed"] is False
        assert suppressed["suppression_policy"]["invalid_count"] == 3
        assert suppressed["suppression_policy"]["suppressed_count"] == 0
        assert suppressed["execution_contract"]["suppression_policy"] == "applied_fail_closed"
        assert {finding["rule_id"] for finding in suppressed["targets"][0]["findings"]} == {finding["rule_id"] for finding in imported_findings}
        assert "SUPPRESSION_POLICY_UNSUPPRESSIBLE_RULE" in {finding["rule_id"] for finding in suppressed["findings"]}


def test_guardian_suppression_recomputes_new_blocking_drift():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app = root / "app"
        route = app / "app" / "api" / "users" / "[id]" / "route.ts"
        route.parent.mkdir(parents=True)
        route.write_text(
            "import { NextResponse } from 'next/server'\n"
            "export async function GET(request: Request, { params }) {\n"
            "  const user = await prisma.user.findUnique({ where: { id: params.id } })\n"
            "  return NextResponse.json(user)\n"
            "}\n",
            encoding="utf-8",
        )
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,audit_profile,notes\n"
            f"test-app,app,workspace,{app},true,local,false,,true,high,team,korean_senior,next route\n",
            encoding="utf-8",
        )
        previous = root / "previous.json"
        previous.write_text(json.dumps({"targets": []}, ensure_ascii=False), encoding="utf-8")
        first_output = root / "guardian-current.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--previous", str(previous), "--output", str(first_output), "--fail-on", "high"]) == 3
        first = json.loads(first_output.read_text(encoding="utf-8"))
        high_finding = next(item for item in first["targets"][0]["findings"] if item["rule_id"] == "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK")
        suppressions = root / "suppressions.csv"
        _write_bound_suppressions(suppressions, first["targets"][0], [high_finding])
        suppressed_output = root / "guardian-suppressed-drift.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--previous", str(previous), "--output", str(suppressed_output), "--fail-on", "high", "--suppressions", str(suppressions)]) == 3
        suppressed = json.loads(suppressed_output.read_text(encoding="utf-8"))
        assert suppressed["guardian_gate"]["passed"] is False
        assert suppressed["targets"][0]["gate"]["passed"] is False
        assert suppressed["drift"]["new_blocking_finding_count"] >= 1
        assert suppressed["suppression_policy"]["suppressed_count"] == 1


def test_guardian_suppression_recomputes_duplicate_shaped_new_blocking_drift():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        imported_report = root / "duplicate-report.json"
        findings = [
            {
                "id": f"passport-{index}",
                "source": "detector",
                "rule_id": "PII_PASSPORT",
                "severity": "high",
                "confidence": "high",
                "title": "Passport-like identifier",
                "file": "app.py",
                "evidence": f"line_hash=duplicate_shape evidence_hash={index}",
                "why_it_matters": "Duplicate-shaped findings must not collapse during drift recomputation.",
                "recommendation": "Remove the exposed identifier.",
            }
            for index in range(1, 3)
        ]
        imported_report.write_text(json.dumps({"raw_free": True, "findings": findings}, ensure_ascii=False), encoding="utf-8")
        manifest = root / "guardian.csv"
        manifest.write_text(
            "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,audit_profile,notes\n"
            f"test-app,duplicates,report,{imported_report},true,local,false,,false,high,team,korean_senior,duplicate drift\n",
            encoding="utf-8",
        )
        previous = root / "previous.json"
        previous.write_text(json.dumps({"targets": []}, ensure_ascii=False), encoding="utf-8")
        first_output = root / "guardian-current.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--previous", str(previous), "--output", str(first_output), "--fail-on", "high"]) == 3
        first = json.loads(first_output.read_text(encoding="utf-8"))
        assert first["drift"]["new_blocking_finding_count"] == 2
        first_finding = first["targets"][0]["findings"][0]
        suppressions = root / "suppressions.csv"
        _write_bound_suppressions(suppressions, first["targets"][0], [first_finding])
        suppressed_output = root / "guardian-suppressed-duplicate-drift.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["guardian", "--manifest", str(manifest), "--previous", str(previous), "--output", str(suppressed_output), "--fail-on", "high", "--suppressions", str(suppressions)]) == 3
        suppressed = json.loads(suppressed_output.read_text(encoding="utf-8"))
        assert suppressed["suppression_policy"]["suppressed_count"] == 1
        assert suppressed["targets"][0]["gate"]["blocking_count"] == 1
        assert suppressed["drift"]["new_blocking_finding_count"] == 1


def test_validation_report_aggregates_manual_design_partner_labels(monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "test-validation-operator-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        guardian_report = root / "guardian.json"
        findings = [
            {
                "target_id": f"app-{index:02d}",
                "rule_id": "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "source": "js-ts-framework",
                "severity": "high",
                "file": f"server-{index}.ts",
                "line_start": 3,
                "evidence": f"detector_subtype=express_idor_route_param line_hash=abc{index}",
            }
            for index in range(1, 6)
        ]
        guardian_report.write_text(
            json.dumps(
                {
                    "targets": [
                        {
                            "app_id": f"owned-{index:02d}",
                            "target_id": finding["target_id"],
                            "findings": [finding],
                        }
                        for index, finding in enumerate(findings, start=1)
                    ]
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        from k_guard_mcp.validation import finding_fingerprint

        review = root / "review.csv"
        rows = ["app_id,target_id,rule_id,finding_fingerprint,verdict,reviewer,notes"]
        for index, finding in enumerate(findings, start=1):
            rows.append(f"owned-{index:02d},{finding['target_id']},JS_TS_EXPRESS_IDOR_ROUTE_PARAM,{finding_fingerprint(finding)},true_positive,cto,confirmed")
        review.write_text(
            "\n".join(rows) + "\n",
            encoding="utf-8",
        )
        output = root / "validation.json"
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["validation-report", "--guardian-report", str(guardian_report), "--review", str(review), "--output", str(output)]) == 0
        report = json.loads(output.read_text(encoding="utf-8"))

    assert report["sample"]["app_count"] == 5
    assert report["sample"]["candidate_count"] == 5
    assert report["sample"]["reviewed_candidate_count"] == 5
    assert report["verdict_counts"]["true_positive"] == 5
    assert report["claim_status"] == "validation_sample_ready"


def test_cli_guardian_fail_on_requires_http_probe_execution_for_gate_scope():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "guardian.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes",
                    "http-01,http,http://127.0.0.1:1,true,local,false,,false,high,team,http row in gate",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        report_output = root / "guardian-report.json"
        gate_output = root / "guardian-gate.json"
        with contextlib.redirect_stdout(io.StringIO()):
            report_code = cli.main(["guardian", "--manifest", str(manifest), "--output", str(report_output)])
        with contextlib.redirect_stdout(io.StringIO()):
            gate_code = cli.main(["guardian", "--manifest", str(manifest), "--output", str(gate_output), "--fail-on", "high"])

        report_payload = json.loads(report_output.read_text(encoding="utf-8"))
        gate_payload = json.loads(gate_output.read_text(encoding="utf-8"))

    assert report_code == 0
    assert report_payload["targets"][0]["status"] == "skipped_probe_requires_run_probes"
    assert report_payload["execution_contract"]["mode"] == "report"
    assert report_payload["execution_contract"]["coverage_gap_target_count"] == 1
    assert gate_code == 3
    assert gate_payload["execution_contract"]["mode"] == "release_gate"
    assert gate_payload["summary"]["coverage_gap_target_count"] == 1
    assert gate_payload["targets"][0]["gate"]["passed"] is False
    rule_ids = {finding["rule_id"] for finding in gate_payload["targets"][0]["findings"]}
    assert "GUARDIAN_HTTP_PROBE_NOT_EXECUTED_IN_GATE" in rule_ids


def test_top_domain_manifest_builder_reads_ranked_zip_without_manual_list():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        archive_path = root / "top-1m.csv.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("top-1m.csv", "1,Example.COM\n2,ignored\n3,Second.example\n4,example.com\n")

        rows = build_manifest_rows(
            source_url=archive_path.as_uri(),
            limit=2,
            start_rank=1,
            cohort="large_general",
            target_prefix="tranco",
            scheme="https",
            timeout=5,
        )

    assert rows == [
        {
            "target_id": "tranco-00001",
            "cohort": "large_general",
            "url": "https://example.com/",
            "rank": "1",
            "domain": "example.com",
            "source_url": archive_path.as_uri(),
        },
        {
            "target_id": "tranco-00002",
            "cohort": "large_general",
            "url": "https://second.example/",
            "rank": "3",
            "domain": "second.example",
            "source_url": archive_path.as_uri(),
        },
    ]


def test_passive_homepage_redirect_boundary_is_not_actionable_high_rate():
    class RedirectHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://www.example.com/")
            self.end_headers()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\nlarge-01,large_general,http://127.0.0.1:{server.server_port}/\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    aggregate = report["aggregate"]["by_cohort"]["large_general"]
    boundary_aggregate = report["aggregate"]["by_hygiene_tier"]["boundary_redirect"]
    row = report["targets"][0]
    assert aggregate["high_critical_target_count"] == 0
    assert aggregate["boundary_target_count"] == 1
    assert aggregate["top_rules"] == []
    assert aggregate["top_observed_rules"] == [{"rule_id": "DYN_REDIRECT_TO_DISALLOWED_HOST", "count": 1}]
    assert boundary_aggregate["target_count"] == 1
    assert boundary_aggregate["high_critical_target_count"] == 0
    assert aggregate["measured_rate"] == 1
    assert aggregate["eligible_measured_rate"] == 1
    assert aggregate["outcome_counts"] == [{"outcome": "http_3xx_boundary_redirect", "count": 1}]
    assert row["rule_ids"] == []
    assert row["observed_rule_ids"] == ["DYN_REDIRECT_TO_DISALLOWED_HOST"]
    assert row["high_or_critical"] is False
    assert row["hygiene_tier"] == "boundary_redirect"
    assert row["outcome"] == "http_3xx_boundary_redirect"
    assert report["passed"] is True
    assert report["release_gate"]["status"] == "warn"


def test_passive_homepage_classifies_same_site_canonical_redirects():
    class FakeResponse:
        status = 302
        url = "https://example.co.kr/"
        headers = {"location": "https://www.example.co.kr/home"}

    assert _registrable_domain_approx("www.example.co.kr") == "example.co.kr"
    assert _redirect_scope(FakeResponse(), "example.co.kr") == "same_site_canonical_redirect"
    assert _domain_role("gtld-servers.net") == "probable_infrastructure"
    assert _domain_role("example.com") == "homepage_candidate"
    assert _domain_role("instagram.com") == "homepage_candidate"
    assert _domain_role("tamburins.com") == "homepage_candidate"
    assert _domain_role("celticconnections.com") == "homepage_candidate"
    assert _domain_role("insuranceclaimcheck.com") == "homepage_candidate"
    assert _domain_role("arkansasbaptist.edu") == "homepage_candidate"
    assert _domain_role("twitter.com") == "homepage_candidate"
    assert _domain_role("amazonaws.com") == "homepage_candidate"
    assert _domain_role("github.io") == "homepage_candidate"
    assert _domain_role("cdn.example.com") == "probable_infrastructure"
    assert _domain_role("akamai.net") == "probable_infrastructure"
    assert _domain_role("tiktokcdn.com") == "probable_infrastructure"
    assert _domain_role("microsoftonline.com") == "probable_infrastructure"
    assert _domain_role("domaincontrol.com") == "probable_infrastructure"
    assert _domain_role("root-servers.net") == "probable_infrastructure"
    assert _domain_role("jsdelivr.net") == "probable_infrastructure"
    candidates = _homepage_candidate_urls(__import__("urllib.parse").parse.urlparse("https://example.com/path?q=1"))
    assert candidates == ["https://example.com/", "http://example.com/", "https://www.example.com/", "http://www.example.com/"]


def test_passive_homepage_skips_probable_infrastructure_domains_from_release_denominator():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "targets.csv"
        manifest.write_text(
            "target_id,cohort,url,rank,domain,source_url\ninfra-01,large_general,https://gtld-servers.net/,3,gtld-servers.net,test\n",
            encoding="utf-8",
        )
        report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=1)

    aggregate = report["aggregate"]["by_cohort"]["large_general"]
    row = report["targets"][0]
    assert row["status"] == "skipped"
    assert row["domain_role"] == "probable_infrastructure"
    assert row["hygiene_tier"] == "not_homepage_candidate"
    assert row["outcome"] == "skipped_probable_infrastructure"
    assert aggregate["not_homepage_candidate_count"] == 1
    assert aggregate["eligible_target_count"] == 0
    assert report["release_gate"]["status"] == "fail"


def test_passive_homepage_hygiene_tiers_separate_quiet_and_hardening_gap():
    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    class GapHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        quiet_server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        gap_server = ThreadingHTTPServer(("127.0.0.1", 0), GapHandler)
        quiet_thread = threading.Thread(target=quiet_server.serve_forever, daemon=True)
        gap_thread = threading.Thread(target=gap_server.serve_forever, daemon=True)
        quiet_thread.start()
        gap_thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                "\n".join(
                    [
                        "target_id,cohort,url,rank,domain,source_url",
                        f"quiet-01,large_general,http://127.0.0.1:{quiet_server.server_port}/quiet,1,quiet.local,test",
                        f"gap-01,large_general,http://127.0.0.1:{gap_server.server_port}/gap,900001,gap.local,test",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=2, delay_ms=0, timeout=2)
        finally:
            quiet_server.shutdown()
            gap_server.shutdown()
            quiet_thread.join(timeout=5)
            gap_thread.join(timeout=5)

    tiers = {row["target_id"]: row["hygiene_tier"] for row in report["targets"]}
    buckets = {row["target_id"]: row["rank_bucket"] for row in report["targets"]}
    assert tiers == {"quiet-01": "well_managed_quiet", "gap-01": "hardening_gap"}
    assert buckets == {"quiet-01": "top_1k", "gap-01": "long_tail"}
    assert report["aggregate"]["by_hygiene_tier"]["well_managed_quiet"]["target_count"] == 1
    assert report["aggregate"]["by_hygiene_tier"]["hardening_gap"]["target_count"] == 1
    assert report["aggregate"]["by_rank_bucket"]["top_1k"]["target_count"] == 1
    assert report["aggregate"]["by_rank_bucket"]["long_tail"]["target_count"] == 1
    assert report["release_gate"]["status"] == "pass"


def test_passive_homepage_retries_failed_requests_once():
    class FlakyHandler(BaseHTTPRequestHandler):
        request_count = 0

        def log_message(self, format, *args):
            return

        def do_GET(self):
            FlakyHandler.request_count += 1
            if FlakyHandler.request_count == 1:
                self.close_connection = True
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        FlakyHandler.request_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), FlakyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\nflaky-01,large_general,http://127.0.0.1:{server.server_port}/\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2, retries=1)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    row = report["targets"][0]
    assert row["status"] == "measured"
    assert row["attempts"] == 2
    assert row["outcome"] == "http_2xx"
    assert report["release_gate"]["status"] == "pass"


def test_passive_homepage_records_fallback_metadata_for_success():
    class OkHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), OkHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\nok-01,large_general,http://127.0.0.1:{server.server_port}/somewhere\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    row = report["targets"][0]
    assert row["effective_url"].endswith("/")
    assert row["fallback_used"] is False
    assert row["candidate_count"] == 1
    assert row["request_audit"]["method"] == "GET"
    assert row["request_audit"]["requested_path"] == "/"
    assert row["request_audit"]["redirect_followed"] is False


def test_passive_homepage_runner_uses_get_root_only():
    class AuditHandler(BaseHTTPRequestHandler):
        calls: list[tuple[str, str]] = []

        def log_message(self, format, *args):
            return

        def do_GET(self):
            AuditHandler.calls.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def do_OPTIONS(self):
            AuditHandler.calls.append(("OPTIONS", self.path))
            self.send_response(204)
            self.end_headers()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        AuditHandler.calls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), AuditHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\nroot-only-01,large_general,http://127.0.0.1:{server.server_port}/deep/path?debug=true\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    row = report["targets"][0]
    assert AuditHandler.calls == [("GET", "/")]
    assert row["request_audit"] == {
        "request_executed": True,
        "method": "GET",
        "requested_path": "/",
        "effective_url": row["effective_url"],
        "attempts": 1,
        "fallback_used": False,
        "candidate_count": 1,
        "redirect_followed": False,
    }


def test_passive_homepage_high_candidate_keeps_raw_free_evidence_and_review():
    secret = "sk-livecandidate1234567890abcdefABCDEF"

    class SecretHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            SecretHandler.calls.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write((f'{{"token":"{secret}"}}').encode("utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        SecretHandler.calls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), SecretHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\ncandidate-01,long_tail_messy_candidate,http://127.0.0.1:{server.server_port}/leaky\n",
                encoding="utf-8",
            )
            unbound_review = root / "unbound-review.csv"
            unbound_review.write_text(
                "target_id,rule_id,verdict,reviewer,notes\n"
                "candidate-01,DYN_RESPONSE_SECRET_LEAK,false_positive,operator,missing evidence anchors\n",
                encoding="utf-8",
            )
            unbound_report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2, review_path=unbound_review)
            unbound_evidence = unbound_report["targets"][0]["finding_evidence"][0]
            assert unbound_evidence["manual_review"]["verdict"] == "needs_review"
            assert unbound_evidence["manual_review"]["recorded_verdict"] == "false_positive"

            review = root / "review.csv"
            review_rows = ["target_id,rule_id,verdict,reviewer,notes,redacted_fingerprint,detector_subtype,body_sha256"]
            for evidence in unbound_report["targets"][0]["finding_evidence"]:
                review_rows.append(
                    "candidate-01,"
                    f"{evidence['rule_id']},false_positive,operator,synthetic local fixture,"
                    f"{evidence['redacted_fingerprint']},{evidence['detector_subtype']},{evidence['body_sha256']}"
                )
            review.write_text("\n".join(review_rows) + "\n", encoding="utf-8")
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2, review_path=review)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    row = report["targets"][0]
    payload = json.dumps(row, ensure_ascii=False)
    assert SecretHandler.calls == [("GET", "/"), ("GET", "/")]
    assert row["high_or_critical"] is True
    assert row["finding_evidence"][0]["rule_id"] == "DYN_RESPONSE_SECRET_LEAK"
    assert row["finding_evidence"][0]["detector_subtype"].startswith("secret_indicator")
    assert row["finding_evidence"][0]["location"] == "body_sample"
    assert row["finding_evidence"][0]["body_sha256"] == row["response_fingerprint"]["body_sha256"]
    assert row["finding_evidence"][0]["manual_review"]["verdict"] == "false_positive"
    assert row["finding_evidence"][0]["manual_review"]["evidence_bound"] is True
    assert row["manual_review"]["verdict"] == "false_positive"
    assert report["candidate_review_queue"]["high_or_critical_count"] == 1
    assert report["candidate_review_queue"]["needs_review_count"] == 0
    assert report["candidate_review_queue"]["high_or_critical_targets"][0]["finding_evidence"][0]["redacted_fingerprint"]
    assert report["candidate_review_queue"]["high_or_critical_targets"][0]["finding_evidence"][0]["body_sha256"] == row["response_fingerprint"]["body_sha256"]
    assert report["release_gate"]["status"] == "pass"
    assert report["claim_boundary"]["passive_homepage_claim"].startswith("GET / only")
    assert secret not in payload


def test_passive_homepage_strong_identifier_candidates_are_listed_for_review():
    class StrongPiiHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"rrn":"901225-1234563"}')

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), StrongPiiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = root / "targets.csv"
            manifest.write_text(
                f"target_id,cohort,url\nstrong-01,long_tail_messy_candidate,http://127.0.0.1:{server.server_port}/\n",
                encoding="utf-8",
            )
            report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=2)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    row = report["targets"][0]
    strong_targets = report["candidate_review_queue"]["strong_identifier_targets"]
    assert row["strong_identifier_detected"] is True
    assert row["finding_evidence"][0]["detector_subtype"] == "strong_identifier_tier_detected"
    assert strong_targets[0]["target_id"] == "strong-01"
    assert strong_targets[0]["detector_subtypes"] == ["strong_identifier_tier_detected"]
    assert strong_targets[0]["finding_evidence"][0]["redacted_fingerprint"]
    assert report["candidate_review_queue"]["needs_review_count"] == 1
    assert report["release_gate"]["status"] == "fail"


def test_passive_homepage_require_operator_key_blocks_public_default(monkeypatch, capsys):
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)

    code = passive_homepage_main(
        [
            "--targets",
            "unused.csv",
            "--output",
            "unused.json",
            "--require-operator-key",
        ]
    )
    output = capsys.readouterr().out

    assert code == 2
    assert "K_GUARD_EVIDENCE_HMAC_KEY" in output


def test_passive_homepage_evidence_boundary_redacts_future_raw_detector_output():
    raw_secret = "sk-rawfuture1234567890abcdefABCDEF"
    raw_email = "raw.person@example.com"

    class FakeFinding:
        rule_id = "DYN_RESPONSE_SECRET_LEAK"
        severity = "critical"
        confidence = "high"
        title = "Future raw detector regression"
        scope = "secret_indicator:SECRET_OPENAI_STYLE_KEY"
        evidence = f"Response body sample matched secret indicators: SECRET_OPENAI_STYLE_KEY {raw_secret} owner={raw_email}"

    class FakeResponse:
        method = "GET"
        probe_path = "/"
        url = "https://example.test/"
        status = 200

    items = _finding_evidence_items(
        "target-raw",
        [FakeFinding()],
        FakeResponse(),
        {
            "body_sha256": "B" * 64,
            "headers_sha256": "H" * 64,
            "content_type": "text/plain",
            "body_truncated": False,
            "inspection_cap_bytes": 4096,
        },
        {},
    )
    payload = json.dumps(items, ensure_ascii=False)

    assert raw_secret not in payload
    assert raw_email not in payload
    assert "<redacted:API_KEY:" in items[0]["redacted_evidence"]
    assert "<redacted:EMAIL:" in items[0]["redacted_evidence"]
    assert items[0]["detector_subtype"] == "secret_indicator:SECRET_OPENAI_STYLE_KEY"


def test_passive_homepage_release_gate_fails_low_measurement_yield():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "targets.csv"
        manifest.write_text("target_id,cohort,url\nclosed-01,large_general,http://127.0.0.1:1/\n", encoding="utf-8")
        report = run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=1)

    aggregate = report["aggregate"]["by_cohort"]["large_general"]
    assert aggregate["measured_count"] == 0
    assert aggregate["measured_rate"] == 0
    assert aggregate["eligible_measured_rate"] == 0
    assert aggregate["unmeasured_count"] == 1
    assert aggregate["outcome_counts"][0]["outcome"].startswith("error_")
    assert report["passed"] is False
    assert report["release_gate"]["status"] == "fail"


def test_passive_homepage_resume_respects_max_target_shard_boundary():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "targets.csv"
        manifest.write_text(
            "\n".join(
                [
                    "target_id,cohort,url",
                    "resume-01,large_general,http://127.0.0.1:1/",
                    "resume-02,large_general,http://127.0.0.1:1/",
                    "resume-03,large_general,http://127.0.0.1:1/",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        checkpoint = root / "checkpoint.jsonl"
        run_passive_homepage_calibration(manifest, max_targets=1, delay_ms=0, timeout=1, checkpoint_jsonl=checkpoint)

        report = run_passive_homepage_calibration(manifest, max_targets=2, delay_ms=0, timeout=1, checkpoint_jsonl=checkpoint, resume=True)

    assert report["source_manifest_count"] == 3
    assert report["target_manifest_count"] == 2
    assert report["completed_count"] == 2
    assert {row["target_id"] for row in report["targets"]} == {"resume-01", "resume-02"}


def test_passive_calibration_summary_combines_reports_with_strict_decision():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        top = root / "top.json"
        tail = root / "tail.json"
        _write_passive_report(top, "large_general", measured=80, targets=100, high=0, strong=0, boundary=10, rules=[])
        _write_passive_report(tail, "messy_candidate_long_tail", measured=90, targets=100, high=0, strong=0, boundary=0, rules=[{"rule_id": "DYN_SECURITY_HEADERS_MISSING", "count": 40}])

        summary = summarize_reports([top, tail])
        markdown = to_markdown(summary)

    assert summary["decision"]["status"] == "pass"
    assert summary["decision"]["observations"]
    assert summary["candidate_review_queue"]["needs_review_count"] == 0
    assert summary["cohorts"]["large_general"]["measured_rate"] == 0.8
    assert summary["cohorts"]["messy_candidate_long_tail"]["top_rules"] == [{"rule_id": "DYN_SECURITY_HEADERS_MISSING", "count": 40}]
    assert "Passive Calibration Summary" in markdown
    assert "80 / eligible 100" in markdown
    assert "Non-Gating Observations" in markdown


def test_passive_calibration_summary_fails_on_strong_identifier():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report = root / "report.json"
        _write_passive_report(report, "large_general", measured=90, targets=100, high=1, strong=1, boundary=0, rules=[{"rule_id": "DYN_RESPONSE_PII_LEAK", "count": 1}])
        data = json.loads(report.read_text(encoding="utf-8"))
        data["candidate_review_queue"] = {
            "high_or_critical_count": 1,
            "strong_identifier_count": 1,
            "unresolved_high_or_critical_count": 1,
            "unresolved_strong_identifier_count": 1,
            "needs_review_count": 1,
            "high_or_critical_targets": [
                {
                    "target_id": "strong-01",
                    "domain": "example.test",
                    "rule_ids": ["DYN_RESPONSE_PII_LEAK"],
                    "detector_subtypes": ["strong_identifier_tier_detected"],
                    "finding_evidence": [{"redacted_fingerprint": "abc123", "body_sha256": "B" * 64, "headers_sha256": "H" * 64}],
                    "manual_review": {"verdict": "needs_review"},
                }
            ],
            "strong_identifier_targets": [
                {
                    "target_id": "strong-01",
                    "domain": "example.test",
                    "rule_ids": ["DYN_RESPONSE_PII_LEAK"],
                    "detector_subtypes": ["strong_identifier_tier_detected"],
                    "finding_evidence": [{"redacted_fingerprint": "abc123", "body_sha256": "B" * 64, "headers_sha256": "H" * 64}],
                    "manual_review": {"verdict": "needs_review"},
                }
            ],
            "needs_review_targets": [
                {
                    "target_id": "strong-01",
                    "domain": "example.test",
                    "rule_ids": ["DYN_RESPONSE_PII_LEAK"],
                    "detector_subtypes": ["strong_identifier_tier_detected"],
                    "finding_evidence": [{"redacted_fingerprint": "abc123", "body_sha256": "B" * 64, "headers_sha256": "H" * 64}],
                    "manual_review": {"verdict": "needs_review"},
                }
            ],
        }
        report.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        summary = summarize_reports([report])

    assert summary["decision"]["status"] == "fail"
    assert summary["candidate_review_queue"]["strong_identifier_targets"][0]["target_id"] == "strong-01"
    assert summary["candidate_review_queue"]["needs_review_count"] == 1
    metrics = {concern["metric"] for concern in summary["decision"]["concerns"]}
    assert {"high_critical", "strong_identifier"} <= metrics


def test_synthetic_deep_probe_calibration_covers_all_scenarios_without_fp_or_fn():
    report = run_synthetic_deep_probe_calibration(target_count=len(SCENARIOS))
    markdown = deep_probe_to_markdown(report)

    assert report["passed"] is True
    assert report["external_network_used"] is False
    assert report["active_profile"] == "deep"
    assert report["claim_label"] == "synthetic_loopback_calibration_only_not_real_site_coverage"
    assert report["aggregate"]["recall"] == 1.0
    assert report["aggregate"]["missing_expected_target_count"] == 0
    assert report["aggregate"]["unexpected_high_target_count"] == 0
    assert report["aggregate"]["unexpected_rule_total"] == 0
    assert report["negative_controls"]["passed"] is True
    control_names = {check["name"] for check in report["negative_controls"]["checks"]}
    assert {"injected_missing_expected_rule_is_detected", "injected_unexpected_rule_is_detected"} <= control_names
    observed = {row["rule_id"] for row in report["aggregate"]["observed_rules"]}
    assert "DYN_EXPOSED_ENV_FILE" in observed
    assert "DYN_UNAUTH_ADMIN_ACCESS" in observed
    assert "DYN_RESPONSE_PII_LEAK" in observed
    assert "Synthetic Loopback Deep Probe Calibration" in markdown
    assert "not 500 real sites" in markdown


def test_inner_core_product_gate_covers_all_audit_planes_without_raw_values():
    report = run_inner_core_product_gate(target_count=len(SCENARIOS))
    markdown = inner_core_to_markdown(report)

    assert report["passed"] is True
    assert report["claim_label"] == "local_synthetic_inner_core_product_gate_not_real_site_coverage"
    assert report["authorization_gate"]["unauthorized_external_blocked"] is True
    assert report["deep_probe"]["target_count"] == len(SCENARIOS)
    assert report["deep_probe"]["recall"] == 1.0
    assert report["deep_probe"]["unexpected_rule_total"] == 0
    assert report["missing_required_rules"] == {"dynamic": [], "workspace": [], "runtime": []}
    assert all(plane["passed"] for plane in report["planes"])
    assert report["flow_graph"]["node_count"] > 0
    assert report["flow_graph"]["edge_count"] > 0
    assert report["raw_free"]["report_payload"] is True
    assert report["raw_free"]["detector_self_scan"]["passed"] is True
    assert report["raw_free"]["detector_self_scan"]["blocking_pii_rules"] == []
    assert report["raw_free"]["detector_self_scan"]["blocking_secret_rules"] == []
    assert "K-Guard Inner-Core Product Gate" in markdown
    assert "not third-party site vulnerability discovery" in markdown


def _write_report(path: Path, findings: list[dict[str, str]]) -> None:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    normalized = []
    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "info")
        summary[severity] += 1
        normalized.append(
            {
                "id": f"finding-{index}",
                "source": "dynamic",
                "rule_id": finding["rule_id"],
                "severity": severity,
                "confidence": "high",
                "title": finding["rule_id"],
                "evidence": finding.get("evidence", ""),
                "why_it_matters": "test",
                "recommendation": "test",
            }
        )
    path.write_text(json.dumps({"summary": summary, "findings": normalized}, ensure_ascii=False), encoding="utf-8")


def _write_passive_report(
    path: Path,
    cohort: str,
    measured: int,
    targets: int,
    high: int,
    strong: int,
    boundary: int,
    rules: list[dict[str, object]],
) -> None:
    aggregate = {
        "target_count": targets,
        "measured_count": measured,
        "measured_rate": round(measured / targets, 4),
        "unmeasured_count": targets - measured,
        "unmeasured_rate": round((targets - measured) / targets, 4),
        "high_critical_target_count": high,
        "high_critical_target_rate": round(high / measured, 4) if measured else 0,
        "strong_identifier_target_count": strong,
        "strong_identifier_target_rate": round(strong / measured, 4) if measured else 0,
        "boundary_target_count": boundary,
        "boundary_target_rate": round(boundary / measured, 4) if measured else 0,
        "top_rules": rules,
        "top_observed_rules": rules,
        "outcome_counts": [{"outcome": "http_2xx", "count": measured}],
        "hygiene_tier_counts": [{"hygiene_tier": "well_managed_quiet", "count": measured}],
    }
    path.write_text(
        json.dumps(
            {
                "passed": high == 0 and strong == 0 and measured / targets >= 0.7,
                "release_gate": {"status": "pass" if high == 0 and strong == 0 and measured / targets >= 0.7 else "fail"},
                "completed_count": targets,
                "target_manifest_count": targets,
                "aggregate": {"by_cohort": {cohort: aggregate}},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
