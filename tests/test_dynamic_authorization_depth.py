from __future__ import annotations

import json
import hashlib
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from k_guard_mcp.dynamic import SafeHttpProbe
from k_guard_mcp.guardian import _auth_acceptance_transition, _merge_http_review_results
from k_guard_mcp.models import ScanResult
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.session import load_session_material


def test_dynamic_probe_rejects_non_http_and_query_targets_before_request() -> None:
    probe = SafeHttpProbe()

    with pytest.raises(ValueError, match="http:// or https://"):
        probe.probe_with_audit("ftp://127.0.0.1/resource", paths=["/"])
    with pytest.raises(ValueError, match="query strings"):
        probe.probe_with_audit("http://127.0.0.1/?token=must-not-leak", paths=["/"])
    with pytest.raises(ValueError, match="origin"):
        probe.probe_with_audit("http://127.0.0.1/private", paths=["/"])
    with pytest.raises(ValueError, match="literal bounded"):
        probe.probe_with_audit("http://127.0.0.1", paths=["/%252e%252e/admin"])


def test_dynamic_probe_connection_failure_is_a_high_incomplete_finding() -> None:
    findings, audit = SafeHttpProbe(timeout=0.2).probe_with_audit("http://127.0.0.1:1", paths=["/"])

    incomplete = next(finding for finding in findings if finding.rule_id == "DYN_PROBE_INCOMPLETE")
    assert incomplete.severity == "high"
    assert any(item.check == "HTTP 요청" and item.result == "error" for item in audit)


def test_session_probe_drops_method_override_headers() -> None:
    received: dict[str, str | None] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            received["override"] = self.headers.get("X-HTTP-Method-Override")
            received["authorization"] = self.headers.get("Authorization")
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        SafeHttpProbe().probe_with_audit(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/private"],
            session_headers={"Authorization": "Bearer test-only", "X-HTTP-Method-Override": "DELETE"},
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert received == {"override": None, "authorization": "Bearer test-only"}


def test_deep_probe_discovers_only_literal_openapi_get_paths() -> None:
    requested: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            requested.append(self.path)
            if self.path == "/openapi.json":
                body = json.dumps(
                    {
                        "openapi": "3.1.0",
                        "paths": {
                            "/api/discovered": {"get": {}},
                            "/api/{id}": {"get": {}},
                            "/api/write-only": {"post": {}},
                            "https://evil.example/steal": {"get": {}},
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200 if self.path == "/api/discovered" else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            active_profile="deep",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    contract = result.metadata["dynamic_probe_contract"]
    assert requested.count("/api/discovered") == 0
    assert not any(path.startswith("/api/") and "{" in path for path in requested)
    assert contract["openapi_discovered_path_count"] == 1
    assert contract["openapi_discovered_paths_executed"] is False
    assert not any(item["path_source"].startswith("openapi_discovered") for item in contract["response_observations"])


def test_dynamic_probe_detects_credentialed_origin_reflection_and_wp_admin() -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path == "/wp-admin/":
                self.wfile.write(b"<html><title>Admin Dashboard</title><body>User Management and System Settings</body></html>")
            else:
                self.wfile.write(b"<html><body>ok</body></html>")

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/", "/wp-admin/"],
            active_profile="deep",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    rules = {finding.rule_id for finding in result.findings}
    assert "DYN_CORS_ORIGIN_REFLECTION_CREDENTIALS" in rules
    assert "DYN_UNAUTH_ADMIN_ACCESS" in rules


def test_auth_acceptance_requires_an_observed_response_transition() -> None:
    path_ref = "path-ref"
    unauth = {
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 401, "auth_wall": True, "response_hash": "before"}
        ]
    }
    accepted = {
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 200, "auth_wall": False, "response_hash": "after"}
        ]
    }
    unchanged = {
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 401, "auth_wall": True, "response_hash": "before"}
        ]
    }

    assert _auth_acceptance_transition(unauth, accepted) == (True, [path_ref])
    assert _auth_acceptance_transition(unauth, unchanged) == (False, [])


def test_guardian_invalid_session_comparison_fails_closed() -> None:
    path_ref = "path-ref"
    unauth_contract = {
        "authenticated": False,
        "coverage_complete": True,
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 401, "auth_wall": True, "response_hash": "same"}
        ],
    }
    auth_contract = {
        "authenticated": True,
        "coverage_complete": True,
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 401, "auth_wall": True, "response_hash": "same"}
        ],
    }
    unauthenticated = ScanResult(metadata={"dynamic_probe_contract": unauth_contract}).finalize()
    authenticated = ScanResult(metadata={"dynamic_probe_contract": auth_contract}).finalize()

    merged = _merge_http_review_results(unauthenticated, authenticated)

    assert merged.metadata["dynamic_probe_contract"]["authenticated_comparison"] is False
    assert "DYN_AUTH_SESSION_ACCEPTANCE_UNPROVEN" in {finding.rule_id for finding in merged.findings}


def test_authenticated_200_requires_identity_assertion_match() -> None:
    path_ref = "path-ref"
    unauth_contract = {
        "authenticated": False,
        "coverage_complete": True,
        "required_path_refs": [path_ref],
        "required_path_reached_refs": [path_ref],
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 401, "auth_wall": True, "response_hash": "before"}
        ],
    }
    auth_contract = {
        "authenticated": True,
        "coverage_complete": True,
        "identity_assertion_supplied": True,
        "identity_assertion_matched": False,
        "required_path_refs": [path_ref],
        "required_path_reached_refs": [path_ref],
        "response_observations": [
            {"path_ref": path_ref, "method": "GET", "status": 200, "auth_wall": False, "response_hash": "error-page"}
        ],
    }

    merged = _merge_http_review_results(
        ScanResult(metadata={"dynamic_probe_contract": unauth_contract}).finalize(),
        ScanResult(metadata={"dynamic_probe_contract": auth_contract}).finalize(),
    )

    contract = merged.metadata["dynamic_probe_contract"]
    assert contract["auth_acceptance_observed"] is True
    assert contract["identity_verified"] is False
    assert contract["authenticated_comparison"] is False
    assert contract["coverage_complete"] is False
    assert "DYN_AUTH_IDENTITY_UNVERIFIED" in {finding.rule_id for finding in merged.findings}


def test_probe_short_content_length_and_budget_exhaustion_fail_closed() -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"short")
            self.close_connection = True

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        findings, audit = SafeHttpProbe().probe_with_audit(base_url, paths=["/"])
        budget_findings, budget_audit = SafeHttpProbe(max_requests=2).probe_with_audit(
            base_url,
            paths=["/first", "/second"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert "DYN_PROBE_INCOMPLETE" in {finding.rule_id for finding in findings}
    assert any(item.check == "HTTP 요청" and item.result == "error" for item in audit)
    assert "DYN_PROBE_BUDGET_EXCEEDED" in {finding.rule_id for finding in budget_findings}
    assert any(item.check == "프로브 제어" and item.result == "error" for item in budget_audit)


def test_cors_checks_each_declared_path_and_null_origin() -> None:
    origins: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def do_OPTIONS(self):
            origin = self.headers.get("Origin", "")
            origins.append((self.path, origin))
            self.send_response(204)
            if self.path == "/api/private" and origin == "null":
                self.send_header("Access-Control-Allow-Origin", "null")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/", "/api/private"],
            required_paths=["/", "/api/private"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert ("/api/private", "https://trusted.example.eviltrusted.example") in origins
    assert ("/api/private", "null") in origins
    finding = next(item for item in result.findings if item.rule_id == "DYN_CORS_NULL_ORIGIN")
    assert "signal_location=response_header" in finding.evidence
    assert result.metadata["dynamic_probe_contract"]["coverage_complete"] is True


def test_custom_probe_paths_and_content_types_are_raw_free() -> None:
    raw_path = "/internal/customer-export"
    raw_content_type = "application/vnd.secret-customer+json"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", raw_content_type + "; profile=internal")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _findings, audit = SafeHttpProbe().probe_with_audit(
            f"http://127.0.0.1:{server.server_port}",
            paths=[raw_path],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.dumps([item.to_dict() for item in audit], ensure_ascii=False)
    assert raw_path not in payload
    assert raw_content_type not in payload
    assert "path-ref" in payload
    assert "content-type-ref" in payload


def test_session_material_is_bounded_to_workspace_origin_and_expiry(tmp_path: Path) -> None:
    base = tmp_path / "workspace"
    base.mkdir()
    outside = tmp_path / "outside-session.json"
    target = "http://127.0.0.1:3100"
    valid_payload = {
        "origin": target,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        "headers": {"Authorization": "Bearer test-only"},
    }
    outside.write_text(json.dumps(valid_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="approved workspace boundary"):
        load_session_material(outside, base_dir=base, target_url=target)

    inside = base / "session.json"
    inside.write_text(json.dumps({**valid_payload, "origin": "http://127.0.0.1:3200"}), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly match"):
        load_session_material(inside, base_dir=base, target_url=target)

    inside.write_text(
        json.dumps({**valid_payload, "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="expired"):
        load_session_material(inside, base_dir=base, target_url=target)


def test_direct_authenticated_probe_without_identity_proof_is_incomplete() -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            body = b'{"error":"invalid token"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/api/me"],
            required_paths=["/api/me"],
            session_headers={"Authorization": "Bearer invalid-test-token"},
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result.metadata["dynamic_probe_contract"]["coverage_complete"] is False
    assert "DYN_AUTH_IDENTITY_UNVERIFIED" in {finding.rule_id for finding in result.findings}


def test_cors_suffix_allowlist_bypass_canary_is_detected() -> None:
    suffix_canary = "https://trusted.example.eviltrusted.example"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def do_OPTIONS(self):
            origin = self.headers.get("Origin", "")
            self.send_response(204)
            if origin.endswith("trusted.example"):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/api/private"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert suffix_canary not in json.dumps(result.to_dict(), ensure_ascii=False)
    assert "DYN_CORS_ORIGIN_REFLECTION_CREDENTIALS" in {finding.rule_id for finding in result.findings}


def test_identity_assertion_hashes_exact_response_bytes_before_decoding() -> None:
    identity_body = b"\xfftest-user"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(identity_body)))
            self.end_headers()
            self.wfile.write(identity_body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(
            f"http://127.0.0.1:{server.server_port}",
            paths=["/api/me"],
            required_paths=["/api/me"],
            session_headers={"Authorization": "Bearer valid-test-token"},
            identity_assertion={
                "path": "/api/me",
                "expected_status": 200,
                "expected_body_sha256": hashlib.sha256(identity_body).hexdigest(),
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    contract = result.metadata["dynamic_probe_contract"]
    assert contract["identity_assertion_matched"] is True
    assert contract["coverage_complete"] is True
    assert "DYN_AUTH_IDENTITY_UNVERIFIED" not in {finding.rule_id for finding in result.findings}
