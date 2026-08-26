import contextlib
import io
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from k_guard_mcp import cli
from k_guard_mcp.dynamic import (
    DEFAULT_MAX_BODY_BYTES,
    HttpResponseSummary,
    MAX_BODY_BYTES_LIMIT,
    MIN_BODY_BYTES_LIMIT,
    SafeHttpProbe,
    _configured_max_body_bytes,
    _normalized_response_headers,
    _response_evidence_hash,
    _selected_probe_paths,
    _sensitive_cache_policy_present,
    _session_cookie_flag_gap,
)
from k_guard_mcp.guardian import _review_contract, _safe_manifest_probe_paths
from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.provenance import evidence_bundle, object_artifact, path_artifact, verify_evidence_bundle
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.severity import validate_confidence, validate_severity
from k_guard_mcp.scoreboard import evaluate_fixture_corpus
from k_guard_mcp.suppression import (
    _load_policy,
    _matching_record,
    _policy_row_error,
    apply_suppressions_to_result,
    write_suppression_template,
)
from k_guard_mcp.validation import (
    _bundle_ref,
    _claim_status,
    _content_ref,
    _guardian_findings,
    _read_reviews,
    _review_error,
    write_validation_review_template,
)


def test_validation_templates_and_invalid_review_boundaries(tmp_path):
    template = tmp_path / "nested" / "validation.csv"
    write_validation_review_template(template)
    assert template.exists()
    assert "finding_fingerprint" in template.read_text(encoding="utf-8")

    reviews, invalid = _read_reviews(tmp_path / "missing.csv")
    assert reviews == {}
    assert invalid[0]["error"] == "review_path_not_found"

    for missing in ("app_id", "target_id", "rule_id", "verdict", "reviewer"):
        row = {
            "app_id": "app",
            "target_id": "target",
            "rule_id": "RULE",
            "finding_fingerprint": "fingerprint",
            "verdict": "true_positive",
            "reviewer": "reviewer",
        }
        row[missing] = ""
        assert _review_error(row) == f"missing_{missing}"
    assert _review_error({"app_id": "a", "target_id": "t", "rule_id": "r", "finding_fingerprint": "f", "verdict": "wrong", "reviewer": "x"}) == "invalid_verdict"
    assert _review_error({"app_id": "a", "target_id": "t", "rule_id": "r", "finding_fingerprint": "", "verdict": "true_positive", "reviewer": "x"}) == "missing_finding_fingerprint"
    assert _review_error({"app_id": "a", "target_id": "t", "rule_id": "r", "finding_fingerprint": "", "verdict": "false_negative", "reviewer": "x"}) == ""


def test_validation_claim_status_covers_every_fail_closed_state():
    assert _claim_status(5, 1, Counter(), 5, 5) == "blocked_invalid_review_labels"
    assert _claim_status(4, 0, Counter(), 5, 5) == "insufficient_design_partner_sample"
    assert _claim_status(21, 0, Counter(), 5, 5) == "sample_scope_too_broad_for_manual_claim"
    assert _claim_status(5, 0, Counter(false_negative=1), 5, 5) == "blocked_false_negatives_need_rule_work"
    assert _claim_status(5, 0, Counter(benign=1), 5, 5) == "blocked_benign_high_critical_labels"
    assert _claim_status(5, 0, Counter(), 4, 4) == "insufficient_candidate_review_coverage"
    assert _claim_status(5, 0, Counter(), 6, 5) == "manual_review_incomplete"
    assert _claim_status(5, 0, Counter(inconclusive=1), 5, 5) == "manual_review_incomplete"
    assert _claim_status(5, 0, Counter(true_positive=5), 5, 5) == "validation_sample_ready"


def test_validation_refs_and_guardian_finding_shape_fail_closed(tmp_path):
    assert _content_ref(tmp_path / "missing.txt")["raw_returned"] is False
    assert _bundle_ref(None)["bundle_sha256"] == ""
    assert _bundle_ref({"bundle_sha256": "abc", "signature": []})["signature_sha256_hash"]
    report = {
        "targets": [
            "bad-row",
            {"target_id": "a", "findings": ["bad-finding", {"rule_id": "R"}]},
        ]
    }
    findings = _guardian_findings(report)
    assert findings == [{"rule_id": "R", "app_id": "", "target_id": "a"}]


def test_evidence_bundle_verifier_rejects_each_malformed_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "operator-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    bundle = evidence_bundle("subject", "producer", [object_artifact("item", {"ok": True})])
    assert verify_evidence_bundle(bundle, require_operator_key=True)
    numeric_digest_bundle = evidence_bundle(
        "numeric-digest",
        "producer",
        [object_artifact("item", {"hash": "1234567890123456"})],
    )
    sanitized_bundle = sanitize_any(numeric_digest_bundle)
    assert sanitized_bundle == numeric_digest_bundle
    assert verify_evidence_bundle(sanitized_bundle, require_operator_key=True)
    assert path_artifact("bad-path", "\0")["exists_at_bundle_time"] is False

    assert not verify_evidence_bundle(None)
    assert not verify_evidence_bundle({"signature": []})
    for mutation in (
        {"schema": "wrong"},
        {"artifacts": []},
        {"artifact_count": "bad"},
        {"artifact_count": 2},
        {"signature": {**bundle["signature"], "algorithm": "none"}},
        {"bundle_sha256": ""},
        {"subject": "tampered"},
        {"signature": {**bundle["signature"], "signature_sha256": "0" * 64}},
    ):
        candidate = json.loads(json.dumps(bundle))
        candidate.update(mutation)
        assert not verify_evidence_bundle(candidate, require_operator_key=True)

    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY")
    assert not verify_evidence_bundle(bundle, require_operator_key=True)
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "operator-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    wrong_mode = json.loads(json.dumps(bundle))
    wrong_mode["signature"]["key_mode"] = "public-default-key"
    assert not verify_evidence_bundle(wrong_mode, require_operator_key=True)


def test_suppression_policy_validation_and_matching_edges(tmp_path):
    template = tmp_path / "suppression.csv"
    write_suppression_template(template)
    assert template.exists()
    missing_policy = _load_policy(tmp_path / "missing.csv")
    assert missing_policy["invalid_findings"][0].rule_id == "SUPPRESSION_POLICY_NOT_FOUND"

    base = {
        "app_id": "app",
        "audit_profile": "korean_senior",
        "release_scope_hash": "a" * 64,
        "target_id": "t",
        "rule_id": "R",
        "finding_fingerprint": "fp",
        "owner": "o",
        "reason": "r",
        "expires": "2999-12-31",
    }
    for field in (
        "app_id",
        "audit_profile",
        "release_scope_hash",
        "target_id",
        "rule_id",
        "finding_fingerprint",
        "owner",
        "reason",
        "expires",
    ):
        row = dict(base)
        row[field] = ""
        assert _policy_row_error(row) == f"missing_{field}"
    assert _policy_row_error({**base, "audit_profile": "standard"}) == "audit_profile_must_be_korean_senior"
    assert _policy_row_error({**base, "release_scope_hash": "short"}) == "invalid_release_scope_hash"
    assert _policy_row_error({**base, "expires": "not-a-date"}) == "invalid_expires"
    assert _policy_row_error({**base, "expires": "2000-01-01"}) == "expired"
    assert _policy_row_error(base) == ""

    finding = {
        "app_id": "app",
        "audit_profile": "korean_senior",
        "release_scope_hash": "a" * 64,
        "rule_id": "R",
        "finding_fingerprint": "fp",
        "target_id": "t",
        "file": "a.py",
        "line_start": 3,
    }
    full = {**base, "target_id": "t", "file": "a.py", "line_start": "3"}
    assert _matching_record(finding, [{**full, "rule_id": "X"}]) is None
    assert _matching_record(finding, [{**full, "finding_fingerprint": "other"}]) is None
    assert _matching_record(finding, [{**full, "target_id": "other"}]) is None
    assert _matching_record(finding, [{**full, "file": "other.py"}]) is None
    assert _matching_record(finding, [{**full, "line_start": "4"}]) is None
    assert _matching_record(finding, [full]) == full


def test_suppression_missing_file_adds_fail_closed_finding(tmp_path):
    result = ScanResult(
        findings=[
            Finding(
                id="1",
                source="test",
                rule_id="R",
                severity="high",
                confidence="high",
                title="risk",
                evidence="raw_free=true",
                why_it_matters="risk",
                recommendation="fix",
            )
        ]
    )
    assert apply_suppressions_to_result(result, None) is result
    guarded = apply_suppressions_to_result(result, tmp_path / "missing.csv")
    assert "SUPPRESSION_POLICY_NOT_FOUND" in {item.rule_id for item in guarded.findings}


def test_cli_templates_and_session_file_validation(tmp_path, monkeypatch):
    for command, filename in (
        ("benchmark-template", "benchmark.csv"),
        ("guardian-template", "guardian.csv"),
        ("suppression-template", "suppression.csv"),
        ("validation-template", "validation.csv"),
    ):
        output = tmp_path / filename
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main([command, "--output", str(output)]) == 0
        assert output.exists()

    monkeypatch.chdir(tmp_path)
    target_url = "http://127.0.0.1:3100"
    expires_at = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    invalid_top = tmp_path / "invalid-top.json"
    invalid_top.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        cli._load_session_headers(str(invalid_top), target_url)
    invalid_headers = tmp_path / "invalid-headers.json"
    invalid_headers.write_text(json.dumps({"origin": target_url, "expires_at": expires_at, "headers": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="headers"):
        cli._load_session_headers(str(invalid_headers), target_url)
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"origin": target_url, "expires_at": expires_at, "headers": {"Host": "x"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        cli._load_session_headers(str(empty), target_url)
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps({"origin": target_url, "expires_at": expires_at, "headers": {"Authorization": "x"}}), encoding="utf-8")
    assert cli._load_session_headers(str(valid), target_url).headers == {"Authorization": "x"}


def test_cli_helper_fail_closed_branches(tmp_path):
    assert cli._probe_allowed_hosts("http://localhost", False) is None
    assert "example.test" in cli._probe_allowed_hosts("https://example.test", True)
    assert cli._probe_authorization_note("https://example.test", False, "note") is None
    assert cli._probe_authorization_note("https://example.test", True, "  reviewed   target ") == "cli_attestation:example.test:reviewed target"
    assert "operator confirmed" in cli._probe_authorization_note("example.test", True, "")
    assert cli._safe_feedback_field(None, "fallback") == "fallback"
    assert cli._guardian_gate({}, None) is None
    gate = cli._guardian_gate({"summary": [], "drift": [], "review_contract": []}, "high")
    assert gate["passed"] is False

    feedback = tmp_path / "feedback.jsonl"
    feedback.write_text("\n{bad\n[]\n" + json.dumps({"type": "fp", "rule": "R", "text": "safe"}) + "\n", encoding="utf-8")
    output = tmp_path / "summary.json"
    summary = cli._export_feedback(feedback, output, 0)
    assert summary["total"] == 1
    assert summary["invalid_lines"] == 2


def test_dynamic_header_and_budget_edge_contracts(monkeypatch):
    assert _session_cookie_flag_gap({}) == []
    assert _session_cookie_flag_gap({"set-cookie": "theme=dark; Path=/"}) == []
    assert _session_cookie_flag_gap({"set-cookie": "session=x; Secure; HttpOnly; SameSite=Lax"}) == []
    assert _session_cookie_flag_gap({"set-cookie": "XSRF-TOKEN=x; Path=/"}) == []
    gaps = _session_cookie_flag_gap({"set-cookie": "session=x; Path=/\nauth=y; SameSite=None"})
    assert set(gaps) >= {"secure", "httponly", "samesite", "secure_for_samesite_none"}
    assert _sensitive_cache_policy_present({"cache-control": "private, max-age=30"})
    assert _sensitive_cache_policy_present({"cache-control": "no-store"})
    assert not _sensitive_cache_policy_present({"cache-control": "x-no-store, public"})
    assert not _sensitive_cache_policy_present({})

    class Headers(dict):
        def get_all(self, name):
            return ["session=a; Secure", "auth=b; HttpOnly"] if name == "Set-Cookie" else None

    normalized = _normalized_response_headers(Headers({"X-Test": "ok"}))
    assert normalized["set-cookie"].count("\n") == 1
    assert _selected_probe_paths(["custom"], "baseline") == ["/custom"]

    monkeypatch.setenv("K_GUARD_HTTP_MAX_BODY_BYTES", "bad")
    assert _configured_max_body_bytes() == DEFAULT_MAX_BODY_BYTES
    monkeypatch.setenv("K_GUARD_HTTP_MAX_BODY_BYTES", "1")
    assert _configured_max_body_bytes() == MIN_BODY_BYTES_LIMIT
    monkeypatch.setenv("K_GUARD_HTTP_MAX_BODY_BYTES", str(MAX_BODY_BYTES_LIMIT * 2))
    assert _configured_max_body_bytes() == MAX_BODY_BYTES_LIMIT


def test_dynamic_redirect_cookie_and_aggregate_request_budget_are_enforced():
    probe = SafeHttpProbe(max_requests=1)
    redirect = HttpResponseSummary(
        url="http://127.0.0.1/login",
        method="GET",
        status=302,
        headers={"location": "/signin", "set-cookie": "session=x; Path=/"},
        body_sample="",
        probe_path="/",
    )
    assert "DYN_SESSION_COOKIE_FLAG_WEAK" in {finding.rule_id for finding in probe._findings_for_response(redirect)}

    response = HttpResponseSummary(
        url="http://127.0.0.1/",
        method="GET",
        status=200,
        headers={},
        body_sample="ok",
        probe_path="/",
    )
    with patch.object(probe, "_request", return_value=response):
        findings, audit_log = probe.probe_with_audit("http://127.0.0.1", paths=["/", "/api"])
    assert len(audit_log) >= 1
    assert "DYN_PROBE_BUDGET_EXCEEDED" in {finding.rule_id for finding in findings}

    changed_volatile_values = HttpResponseSummary(
        url=redirect.url,
        method=redirect.method,
        status=redirect.status,
        headers={"location": "/signin", "date": "tomorrow", "set-cookie": "session=another-value; Path=/"},
        body_sample=redirect.body_sample,
        probe_path=redirect.probe_path,
    )
    redirect.headers["date"] = "today"
    assert _response_evidence_hash(redirect) == _response_evidence_hash(changed_volatile_values)


def test_guardian_manifest_path_and_profile_contract_edges():
    paths = _safe_manifest_probe_paths("/ok|/ok|https://evil.test/x|/../secret|/{id}|/search?q=1")
    assert paths == ["/ok", "/search?q=1"]

    complete_intent = {
        "business_purpose_explicit_complete": True,
        "data_class_complete": True,
        "user_scope_complete": True,
        "scope_assertion_complete": True,
    }
    workspace = {
        "audit_profile": "standard",
        "status": "completed",
        "kind": "workspace",
        "requested_review": {"flow_analysis": True},
        "review_evidence": {"review_coverage": {"source_kind": "workspace", "flow_analysis_executed": True}},
    }
    standard = _review_contract([workspace], complete_intent, release_gate_enabled=True)
    assert standard["passed"] is False
    assert standard["coverage_grade"] == "incomplete"
    assert standard["canonical_release_authority"] is False
    assert standard["report_only"] is True
    assert _review_contract([], complete_intent, release_gate_enabled=True)["passed"] is False

    strict = dict(workspace)
    strict["audit_profile"] = "korean_senior"
    mixed = _review_contract([workspace, strict], complete_intent, release_gate_enabled=True)
    assert mixed["profile"] == "invalid_or_mixed"
    assert mixed["passed"] is False


def test_severity_and_confidence_validation_reject_unknown_values():
    assert validate_severity("high") == "high"
    assert validate_confidence("medium") == "medium"
    with pytest.raises(ValueError):
        validate_severity("urgent")
    with pytest.raises(ValueError):
        validate_confidence("certain")


def test_guardian_ci_template_executes_strict_dynamic_scope():
    workflow = Path("docs/templates/github-actions/guardian-release-gate.yml").read_text(encoding="utf-8")
    assert "--run-probes" in workflow
    assert "--fail-on high" in workflow


def test_fixture_scoreboard_does_not_return_raw_case_names_or_paths(tmp_path):
    corpus = tmp_path / "patient-user@example.com-corpus.json"
    corpus.write_text(
        json.dumps(
            {
                "positives": [
                    {
                        "name": "홍길동 010-1234-5678",
                        "text": "email=hong@example.com",
                        "expected_any": ["PII_EMAIL"],
                    }
                ],
                "negatives": [{"name": "private-patient-note-88", "text": "hello world"}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    report = evaluate_fixture_corpus(corpus)
    payload = json.dumps(report, ensure_ascii=False)
    assert report["passed"] is False
    assert report["workspace_case_count"] == 0
    for raw in ("patient-user@example.com", "홍길동", "010-1234-5678", "private-patient-note-88"):
        assert raw not in payload
