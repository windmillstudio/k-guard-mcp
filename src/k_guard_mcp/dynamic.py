from __future__ import annotations

import ipaddress
import http.client
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass

from k_guard_mcp.detectors import PiiDetector, SecretDetector
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Entity, Finding
from k_guard_mcp.privacy_taxonomy import metadata_for_rule


DEFAULT_PATHS = [
    "/",
    "/admin",
    "/api",
    "/api/users",
    "/swagger.json",
    "/openapi.json",
    "/_next/static/chunks/app.js.map",
]
DEFAULT_MAX_OPENAPI_DISCOVERY_PATHS = 12

DEFAULT_ACTIVE_DEEP_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/backup.zip",
    "/server-status",
    "/phpinfo.php",
    "/actuator/env",
    "/debug",
    "/debug/vars",
    "/administrator",
    "/admin/",
    "/wp-admin/",
]

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
MAX_BODY_BYTES_ENV = "K_GUARD_HTTP_MAX_BODY_BYTES"
MAX_BODY_BYTES_LIMIT = 10 * 1024 * 1024
MIN_BODY_BYTES_LIMIT = 4 * 1024
DEFAULT_MAX_TOTAL_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_SECONDS = 30.0
DEFAULT_MAX_REQUESTS = 100
UNTRUSTED_CORS_ORIGINS = (
    "https://trusted.example.eviltrusted.example",
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _PinnedConnectionMixin:
    def __init__(self, host, *args, pinned_ip: str, **kwargs):  # type: ignore[no-untyped-def]
        self._k_guard_pinned_ip = pinned_ip
        super().__init__(host, *args, **kwargs)
        self._create_connection = self._create_pinned_connection

    def _create_pinned_connection(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):  # type: ignore[no-untyped-def]
        return socket.create_connection(
            (self._k_guard_pinned_ip, address[1]),
            timeout,
            source_address,
        )


class _PinnedHTTPConnection(_PinnedConnectionMixin, http.client.HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, http.client.HTTPSConnection):
    pass


def _request_pinned_ip(request: urllib.request.Request) -> str:
    pinned_ip = getattr(request, "_k_guard_pinned_ip", "")
    if not isinstance(pinned_ip, str) or not pinned_ip:
        raise urllib.error.URLError("K-Guard refused an unpinned outbound probe connection")
    return pinned_ip


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request):  # type: ignore[no-untyped-def]
        pinned_ip = _request_pinned_ip(request)
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPConnection(
                host,
                pinned_ip=pinned_ip,
                **kwargs,
            ),
            request,
        )


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):  # type: ignore[no-untyped-def]
        pinned_ip = _request_pinned_ip(request)
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(
                host,
                pinned_ip=pinned_ip,
                **kwargs,
            ),
            request,
            context=self._context,
            check_hostname=self._check_hostname,
        )


@dataclass
class HttpResponseSummary:
    url: str
    method: str
    status: int | None
    headers: dict[str, str]
    body_sample: str
    body_sha256: str = ""
    probe_path: str = ""
    body_truncated: bool = False
    inspection_cap_bytes: int = DEFAULT_MAX_BODY_BYTES
    inspected_body_bytes: int = 0
    authenticated: bool = False
    path_source: str = "configured"
    error: str | None = None
    identity_assertion_match: bool = False


@dataclass(frozen=True)
class DynamicPiiSignal:
    kind: str
    severity: str
    confidence: str
    title: str
    evidence: str
    recommendation: str
    subtype: str


@dataclass(frozen=True)
class ProbeAuditLog:
    check: str
    result: str
    method: str
    url: str
    status: int | None
    probe_path: str
    content_type: str
    looked_for: str
    outcome: str
    rule_ids: tuple[str, ...] = ()
    response_hash: str = ""
    response_class: str = "unknown"
    auth_wall: bool = False
    private_data_signal: bool = False
    authenticated: bool = False
    path_source: str = "configured"
    probe_path_ref: str = ""
    identity_assertion_match: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "check": self.check,
            "result": self.result,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "probe_path": self.probe_path,
            "content_type": self.content_type,
            "looked_for": self.looked_for,
            "outcome": self.outcome,
            "rule_ids": list(self.rule_ids),
            "response_hash": self.response_hash,
            "response_class": self.response_class,
            "auth_wall": self.auth_wall,
            "private_data_signal": self.private_data_signal,
            "authenticated": self.authenticated,
            "path_source": self.path_source,
            "probe_path_ref": self.probe_path_ref,
            "identity_assertion_match": self.identity_assertion_match,
        }


class SafeHttpProbe:
    def __init__(
        self,
        id_factory: IdFactory | None = None,
        allowed_hosts: set[str] | None = None,
        timeout: float = 3.0,
        max_body_bytes: int | None = None,
        max_total_body_bytes: int = DEFAULT_MAX_TOTAL_BODY_BYTES,
        max_total_seconds: float = DEFAULT_MAX_TOTAL_SECONDS,
        max_requests: int = DEFAULT_MAX_REQUESTS,
    ) -> None:
        self.ids = id_factory or IdFactory()
        self.allowed_hosts = allowed_hosts or ALLOWED_HOSTS
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes if max_body_bytes is not None else _configured_max_body_bytes()
        self.max_total_body_bytes = max(MIN_BODY_BYTES_LIMIT, int(max_total_body_bytes))
        self.max_total_seconds = max(1.0, float(max_total_seconds))
        self.max_requests = max(1, int(max_requests))
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirectHandler,
            PinnedHTTPHandler,
            PinnedHTTPSHandler,
        )
        self.secret_detector = SecretDetector(self.ids)
        self.pii_detector = PiiDetector(self.ids)

    def probe(self, base_url: str, paths: list[str] | None = None, session_headers: dict[str, str] | None = None, active_profile: str = "baseline", identity_assertion: dict[str, object] | None = None) -> list[Finding]:
        findings, _ = self.probe_with_audit(base_url, paths, session_headers=session_headers, active_profile=active_profile, identity_assertion=identity_assertion)
        return findings

    def probe_with_audit(self, base_url: str, paths: list[str] | None = None, session_headers: dict[str, str] | None = None, active_profile: str = "baseline", identity_assertion: dict[str, object] | None = None) -> tuple[list[Finding], list[ProbeAuditLog]]:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme.casefold() not in {"http", "https"}:
            raise ValueError("Dynamic probe requires an explicit http:// or https:// target.")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Dynamic probe targets cannot include userinfo, query strings, or fragments.")
        if parsed.path not in {"", "/"}:
            raise ValueError("Dynamic probe target must be an origin; declare paths separately.")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Dynamic probe target port is invalid.") from exc
        if not _allowed_host(parsed.hostname, self.allowed_hosts):
            raise ValueError(f"Dynamic probe blocked for host {parsed.hostname!r}. Add an explicit allowlist before probing external hosts.")
        base = _pin_loopback_url(base_url).rstrip("/")
        findings: list[Finding] = []
        audit_log: list[ProbeAuditLog] = []
        selected_paths = _selected_probe_paths(paths, active_profile)
        path_sources = {
            path: "declared" if paths is not None else "deep_profile" if active_profile == "deep" else "baseline_profile"
            for path in selected_paths
        }
        seen_paths = set(selected_paths)
        openapi_discovery_count = 0
        started = time.monotonic()
        total_body_bytes = 0
        request_count = 0
        budget_reason = ""
        authenticated = _session_headers_indicate_authentication(session_headers)
        for path in selected_paths:
            if request_count >= self.max_requests:
                budget_reason = "request_count"
                break
            elapsed = time.monotonic() - started
            if elapsed >= self.max_total_seconds:
                budget_reason = "elapsed_time"
                break
            remaining_body_bytes = self.max_total_body_bytes - total_body_bytes
            if remaining_body_bytes < MIN_BODY_BYTES_LIMIT:
                budget_reason = "response_bytes"
                break
            url = base + (path if path.startswith("/") else "/" + path)
            response = self._request(
                url,
                "GET",
                headers=_probe_headers(session_headers),
                probe_path=path,
                authenticated=authenticated,
                path_source=path_sources.get(path, "configured"),
                identity_assertion=identity_assertion,
                max_body_bytes=min(self.max_body_bytes, remaining_body_bytes),
                timeout=min(self.timeout, max(0.1, self.max_total_seconds - elapsed)),
            )
            request_count += 1
            total_body_bytes += response.inspected_body_bytes
            response_findings = self._findings_for_response(response)
            findings.extend(response_findings)
            audit_log.extend(self._audit_log_for_response(response, response_findings))
            if active_profile == "deep" and _is_openapi_path(path) and _looks_like_openapi_document(response):
                remaining_discovery = DEFAULT_MAX_OPENAPI_DISCOVERY_PATHS - openapi_discovery_count
                for discovered_path in _safe_openapi_get_paths(response, max_paths=max(0, remaining_discovery)):
                    if discovered_path in seen_paths:
                        continue
                    seen_paths.add(discovered_path)
                    audit_log.append(
                        ProbeAuditLog(
                            check="OpenAPI 경로 발견",
                            result="not_executed",
                            method="DISCOVERY",
                            url=_redacted_probe_url(response.url),
                            status=response.status,
                            probe_path=_redacted_probe_path(discovered_path),
                            content_type=_redacted_content_type(response.headers.get("content-type", "")),
                            looked_for="OpenAPI GET 경로를 실행 후보로만 수집",
                            outcome="명시적 public_endpoints 승인 전에는 요청하지 않음",
                            response_hash=_response_evidence_hash(response),
                            response_class="discovered_not_executed",
                            authenticated=authenticated,
                            path_source="openapi_discovered_not_executed",
                            probe_path_ref=evidence_hash(discovered_path),
                        )
                    )
                    openapi_discovery_count += 1
                    if openapi_discovery_count >= DEFAULT_MAX_OPENAPI_DISCOVERY_PATHS:
                        break
            if path == "/" and response.status is None:
                break
            for cors_origin in (*UNTRUSTED_CORS_ORIGINS, "null"):
                if request_count >= self.max_requests or time.monotonic() - started >= self.max_total_seconds:
                    budget_reason = "request_count_or_elapsed_time"
                    break
                if self.max_total_body_bytes - total_body_bytes < MIN_BODY_BYTES_LIMIT:
                    budget_reason = "response_bytes"
                    break
                options_response = self._request(
                    url,
                    "OPTIONS",
                    {"Origin": cors_origin, "Access-Control-Request-Method": "GET"},
                    probe_path=path,
                    path_source=path_sources.get(path, "configured"),
                    max_body_bytes=min(self.max_body_bytes, max(MIN_BODY_BYTES_LIMIT, self.max_total_body_bytes - total_body_bytes)),
                    timeout=min(self.timeout, max(0.1, self.max_total_seconds - (time.monotonic() - started))),
                )
                request_count += 1
                total_body_bytes += options_response.inspected_body_bytes
                option_findings = self._findings_for_response(options_response)
                findings.extend(option_findings)
                audit_log.extend(self._audit_log_for_response(options_response, option_findings))
            if budget_reason:
                break
        if budget_reason:
            findings.append(self._probe_budget_finding(budget_reason, request_count, total_body_bytes, time.monotonic() - started))
            audit_log.append(
                ProbeAuditLog(
                    check="프로브 제어",
                    result="error",
                    method="CONTROL",
                    url=_redacted_probe_url(base),
                    status=None,
                    probe_path="<remaining-scope>",
                    content_type="not-applicable",
                    looked_for="승인된 전체 경로가 자원 한도 안에서 실행됐는지 확인",
                    outcome="자원 한도 도달로 남은 경로를 실행하지 않음",
                    path_source="control",
                    probe_path_ref=evidence_hash("remaining-scope"),
                )
            )
        incomplete_requests = sum(1 for item in audit_log if item.check == "HTTP 요청" and item.result == "error")
        if incomplete_requests:
            findings.append(self._probe_incomplete_finding(incomplete_requests, request_count))
        return findings, audit_log

    def _request(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None = None,
        probe_path: str = "",
        authenticated: bool = False,
        path_source: str = "configured",
        identity_assertion: dict[str, object] | None = None,
        max_body_bytes: int | None = None,
        timeout: float | None = None,
    ) -> HttpResponseSummary:
        url = _pin_loopback_url(url)
        body_limit = self.max_body_bytes if max_body_bytes is None else max(MIN_BODY_BYTES_LIMIT, int(max_body_bytes))
        request_timeout = self.timeout if timeout is None else max(0.1, float(timeout))
        request_deadline = time.monotonic() + request_timeout
        request = urllib.request.Request(url, method=method, headers=headers or {"User-Agent": "k-guard-mcp/0.1"})
        try:
            parsed = urllib.parse.urlparse(url)
            pinned_ip = _resolved_probe_address(parsed.hostname, self.allowed_hosts)
            if pinned_ip is None:
                return HttpResponseSummary(
                    url=url,
                    method=method,
                    status=None,
                    headers={},
                    body_sample="",
                    probe_path=probe_path,
                    authenticated=authenticated,
                    path_source=path_source,
                    error=f"request_error=disallowed_host host_ref={evidence_hash(str(parsed.hostname or ''))} raw_returned=false",
                )
            setattr(request, "_k_guard_pinned_ip", pinned_ip)
            with self.opener.open(request, timeout=request_timeout) as response:
                body, truncated, body_byte_count, deadline_exceeded, length_mismatch, body_sha256 = _read_limited_body(response, body_limit, request_deadline)
                summary = HttpResponseSummary(
                    url=url,
                    method=method,
                    status=response.status,
                    headers=_normalized_response_headers(response.headers),
                    body_sample=body,
                    body_sha256=body_sha256,
                    probe_path=probe_path,
                    body_truncated=truncated,
                    inspection_cap_bytes=body_limit,
                    inspected_body_bytes=body_byte_count,
                    authenticated=authenticated,
                    path_source=path_source,
                    error=_body_read_error(truncated, deadline_exceeded, length_mismatch),
                )
                summary.identity_assertion_match = _identity_assertion_matches(summary, identity_assertion)
                return summary
        except urllib.error.HTTPError as exc:
            body, truncated, body_byte_count, deadline_exceeded, length_mismatch, body_sha256 = _read_limited_body(exc, body_limit, request_deadline)
            summary = HttpResponseSummary(
                url=url,
                method=method,
                status=exc.code,
                headers=_normalized_response_headers(exc.headers),
                body_sample=body,
                body_sha256=body_sha256,
                probe_path=probe_path,
                body_truncated=truncated,
                inspection_cap_bytes=body_limit,
                inspected_body_bytes=body_byte_count,
                authenticated=authenticated,
                path_source=path_source,
                error="; ".join(part for part in (f"http_status_error={exc.code}", _body_read_error(truncated, deadline_exceeded, length_mismatch)) if part),
            )
            summary.identity_assertion_match = _identity_assertion_matches(summary, identity_assertion)
            return summary
        except Exception as exc:  # network errors are probe observations, not scanner crashes
            return HttpResponseSummary(
                url=url,
                method=method,
                status=None,
                headers={},
                body_sample="",
                probe_path=probe_path,
                authenticated=authenticated,
                path_source=path_source,
                error=_network_error_observation(exc),
            )

    def _findings_for_response(self, response: HttpResponseSummary) -> list[Finding]:
        findings: list[Finding] = []
        if response.status is None:
            return findings
        content_type = response.headers.get("content-type", "")
        cookie_gap = _session_cookie_flag_gap(response.headers)
        if cookie_gap:
            findings.append(
                self._finding(
                    "DYN_SESSION_COOKIE_FLAG_WEAK",
                    "high",
                    "high",
                    "Session-like cookie is missing a required security flag",
                    response,
                    "Session-like Set-Cookie header flag gap: " + ", ".join(cookie_gap),
                    "Set authentication cookies with Secure, HttpOnly, and an intentional SameSite policy; use SameSite=None only with Secure.",
                )
            )
        if response.status in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "")
            target = urllib.parse.urljoin(response.url, location)
            if location and _normalized_origin(target) != _normalized_origin(response.url):
                findings.append(self._finding("DYN_REDIRECT_TO_DISALLOWED_HOST", "high", "high", "Redirect leaves the authorized origin", response, "The response redirects to a different scheme, host, or port; the probe did not follow it.", "Keep redirects on the reviewed origin or authorize and audit the destination as a separate target."))
            return findings
        if not response.authenticated and _is_admin_probe_path(response.probe_path) and response.status == 200:
            admin_finding = self._admin_route_finding(response)
            if admin_finding:
                findings.append(admin_finding)
        sensitive_findings = self._sensitive_body_findings(response)
        findings.extend(sensitive_findings)
        if not response.authenticated and response.method == "GET" and response.status == 200 and "json" in content_type:
            sensitive_response = any(item.rule_id in {"DYN_RESPONSE_SECRET_LEAK", "DYN_RESPONSE_PII_LEAK"} for item in sensitive_findings)
            if sensitive_response or _private_api_json_signal(response.body_sample):
                findings.append(self._finding("DYN_UNAUTH_API_JSON", "high", "medium", "Potentially private API data returned without auth", response, "An unauthenticated API response contained sensitive or private-record structure.", "Require authentication or remove private fields; if this endpoint is intentionally public, document and test its field allowlist."))
            elif response.probe_path.startswith("/api") or response.probe_path not in DEFAULT_PATHS:
                findings.append(self._finding("DYN_PUBLIC_API_JSON_REVIEW", "info", "low", "Public API JSON response needs intent review", response, "An unauthenticated API returned JSON without private-record or sensitive-data indicators.", "Confirm the endpoint is intentionally public and keep an explicit response-field allowlist."))
        if response.authenticated and any(item.rule_id in {"DYN_RESPONSE_SECRET_LEAK", "DYN_RESPONSE_PII_LEAK"} for item in sensitive_findings) and not _sensitive_cache_policy_present(response.headers):
            findings.append(
                self._finding(
                    "DYN_SENSITIVE_RESPONSE_CACHE_POLICY_WEAK",
                    "high",
                    "medium",
                    "Sensitive response lacks a private/no-store cache policy",
                    response,
                    "A sensitive response signal was present without Cache-Control private or no-store.",
                    "Return Cache-Control: no-store for highly sensitive responses, or private with a reviewed short lifetime where caching is required.",
                )
            )
        if response.probe_path.endswith(".map") and response.status == 200 and _looks_like_source_map(response):
            findings.append(self._finding("DYN_SOURCE_MAP_ACCESSIBLE", "medium", "high", "Source map is publicly accessible", response, "A source map was reachable from the running app.", "Disable public production source maps or restrict access."))
        if _is_openapi_path(response.probe_path) and response.status == 200 and _looks_like_openapi_document(response):
            findings.append(self._finding("DYN_OPENAPI_EXPOSED", "medium", "medium", "OpenAPI/Swagger document exposed", response, "API schema is reachable without auth.", "Restrict API docs in production if they expose sensitive routes."))
        if response.method == "OPTIONS":
            origin = response.headers.get("access-control-allow-origin", "")
            credentials = response.headers.get("access-control-allow-credentials", "")
            if origin == "*" and credentials.lower() == "true":
                findings.append(self._finding("DYN_CORS_WILDCARD_CREDENTIALS", "high", "high", "CORS allows wildcard origin with credentials", response, "CORS response combines wildcard origin and credentials.", "Use a strict origin allowlist and avoid credentialed wildcard CORS."))
            elif origin.casefold() in UNTRUSTED_CORS_ORIGINS and credentials.lower() == "true":
                findings.append(self._finding("DYN_CORS_ORIGIN_REFLECTION_CREDENTIALS", "critical", "high", "CORS reflects an untrusted origin with credentials", response, "CORS response reflected the probe origin and allowed credentials.", "Replace origin reflection with an exact trusted-origin allowlist and disable credentialed CORS for public endpoints."))
            elif origin.casefold() in UNTRUSTED_CORS_ORIGINS:
                findings.append(self._finding("DYN_CORS_ORIGIN_REFLECTION", "high", "high", "CORS reflects an untrusted origin", response, "CORS response reflected the probe origin.", "Validate Origin against an exact trusted-origin allowlist before returning Access-Control-Allow-Origin."))
            elif origin.casefold() == "null":
                findings.append(self._finding("DYN_CORS_NULL_ORIGIN", "high", "medium", "CORS allows the null origin", response, "CORS response explicitly allowed the null origin.", "Do not trust null origins; allow only exact HTTPS application origins that require browser access."))
            elif origin == "*":
                findings.append(self._finding("DYN_CORS_WILDCARD", "medium", "medium", "CORS wildcard origin", response, "CORS response allows all origins.", "Use explicit trusted origins."))
        if response.probe_path == "/" and response.status == 200:
            missing = [header for header in ("content-security-policy", "x-content-type-options", "x-frame-options") if header not in response.headers]
            if missing:
                findings.append(self._finding("DYN_SECURITY_HEADERS_MISSING", "medium", "medium", "Security headers missing", response, "Missing headers: " + ", ".join(missing), "Add security headers appropriate for the app."))
            if urllib.parse.urlparse(response.url).scheme.lower() == "https" and "strict-transport-security" not in response.headers:
                findings.append(
                    self._finding(
                        "DYN_HSTS_MISSING",
                        "medium",
                        "high",
                        "HTTPS response is missing Strict-Transport-Security",
                        response,
                        "HTTPS root response did not include Strict-Transport-Security.",
                        "Add HSTS after confirming all production subdomains and redirects are HTTPS-ready.",
                    )
                )
        if _looks_like_debug_error(response.body_sample):
            findings.append(self._finding("DYN_DEBUG_ERROR_LEAK", "high", "medium", "Debug error details exposed", response, "Response body contains stack trace or internal error details.", "Disable debug pages and sanitize production errors."))
        if re.search(r"<title>Index of /|Directory listing for", response.body_sample, re.IGNORECASE):
            findings.append(self._finding("DYN_DIRECTORY_LISTING", "medium", "medium", "Directory listing exposed", response, "HTTP response appears to expose directory listing.", "Disable directory listing."))
        findings.extend(self._deep_exposure_findings(response))
        return findings

    def _audit_log_for_response(self, response: HttpResponseSummary, findings: list[Finding]) -> list[ProbeAuditLog]:
        by_rule = {finding.rule_id for finding in findings}
        body_incomplete = _response_body_incomplete(response)
        logs = [
            self._audit(
                response,
                "HTTP 요청",
                "error" if response.status is None or body_incomplete else "pass",
                "고정 경로에 안전한 GET/OPTIONS 요청을 보냄",
                (
                    f"응답 본문 검사가 완료되지 않음: inspected_bytes={response.inspected_body_bytes} cap_bytes={response.inspection_cap_bytes} reason={response.error or 'response_body_truncated'}"
                    if body_incomplete
                        else response.error or f"상태 {response.status}, content-type {_redacted_content_type(response.headers.get('content-type', ''))} 응답 확인"
                ),
                tuple(sorted(by_rule)),
                coverage_complete=not body_incomplete,
            )
        ]
        if response.status is None or body_incomplete:
            return logs

        if response.status in {301, 302, 303, 307, 308}:
            if "DYN_REDIRECT_TO_DISALLOWED_HOST" in by_rule:
                logs.append(self._audit(response, "리다이렉트 경계", "finding", "Location 헤더가 입력한 origin 밖으로 나가는지 확인", "입력한 사이트 밖으로 이동하는 redirect라 따라가지 않음", ("DYN_REDIRECT_TO_DISALLOWED_HOST",)))
            else:
                logs.append(self._audit(response, "리다이렉트 경계", "pass", "Location 헤더가 입력한 origin 밖으로 나가는지 확인", "허용 범위 안의 redirect 또는 추가 위험 신호 없음"))
            return logs

        if response.probe_path == "/" and response.method == "GET":
            missing = [header for header in ("content-security-policy", "x-content-type-options", "x-frame-options") if header not in response.headers]
            if "DYN_SECURITY_HEADERS_MISSING" in by_rule:
                logs.append(self._audit(response, "보안 헤더", "finding", "CSP, X-Content-Type-Options, X-Frame-Options 존재 여부 확인", "빠진 헤더: " + ", ".join(missing), ("DYN_SECURITY_HEADERS_MISSING",)))
            else:
                logs.append(self._audit(response, "보안 헤더", "pass", "CSP, X-Content-Type-Options, X-Frame-Options 존재 여부 확인", "필수 보안 헤더 위험 신호 없음"))

        if _is_admin_probe_path(response.probe_path) and response.method == "GET":
            if "DYN_UNAUTH_ADMIN_ACCESS" in by_rule:
                logs.append(self._audit(response, "관리자 경로", "finding", "200 응답 뒤 로그인/SPA/관리 기능 단서를 확인", "관리자 기능 단서가 보여 위험으로 분류", ("DYN_UNAUTH_ADMIN_ACCESS",)))
            elif "DYN_ADMIN_ROUTE_REVIEW_REQUIRED" in by_rule:
                logs.append(self._audit(response, "관리자 경로", "review", "200 응답 뒤 로그인/SPA/관리 기능 단서를 확인", "관리 기능 단서는 명확하지 않아 확인 필요로 낮게 분류", ("DYN_ADMIN_ROUTE_REVIEW_REQUIRED",)))
            else:
                logs.append(self._audit(response, "관리자 경로", "pass", "200 응답 뒤 로그인/SPA/관리 기능 단서를 확인", "로그인 화면, SPA shell, 비정상 상태, 또는 관리 기능 단서 없음"))

        if response.probe_path.startswith("/api") and response.method == "GET":
            if "DYN_UNAUTH_API_JSON" in by_rule:
                logs.append(self._audit(response, "API JSON", "finding", "인증 없는 GET이 JSON을 반환하는지 확인", "로그인 없는 JSON 응답이라 공개 API 여부 확인 필요", ("DYN_UNAUTH_API_JSON",)))
            elif "DYN_PUBLIC_API_JSON_REVIEW" in by_rule:
                logs.append(self._audit(response, "API JSON", "review", "인증 없는 GET이 JSON을 반환하는지 확인", "민감·비공개 레코드 단서는 없으며 공개 의도만 확인 필요", ("DYN_PUBLIC_API_JSON_REVIEW",)))
            else:
                logs.append(self._audit(response, "API JSON", "pass", "인증 없는 GET이 JSON을 반환하는지 확인", "JSON 200 응답이 아니거나 공개 데이터로 볼 수 있어 API 노출 카드 없음"))

        if response.method == "GET":
            pii_rules = tuple(rule for rule in ("DYN_RESPONSE_SECRET_LEAK", "DYN_RESPONSE_PII_LEAK", "DYN_RESPONSE_PII_REVIEW") if rule in by_rule)
            if pii_rules:
                logs.append(self._audit(response, "응답 민감정보", "finding" if "DYN_RESPONSE_SECRET_LEAK" in pii_rules or "DYN_RESPONSE_PII_LEAK" in pii_rules else "review", "API key/secret, 강한 식별자, 연결 레코드, 뭉텅이 연락처 tier 확인", _finding_evidence(findings, set(pii_rules)), pii_rules))
            else:
                logs.append(self._audit(response, "응답 민감정보", "pass", "API key/secret, 강한 식별자, 연결 레코드, 뭉텅이 연락처 tier 확인", "공개 안내 연락처/대표자명 또는 단일 약한 단서는 표시 대상이 아니며 위험 tier 없음"))

        if _is_openapi_path(response.probe_path) and response.method == "GET":
            if "DYN_OPENAPI_EXPOSED" in by_rule:
                logs.append(self._audit(response, "API 문서", "finding", "200 응답이 실제 openapi/swagger JSON 구조인지 확인", "openapi/swagger와 paths 구조가 보여 API 문서 노출로 분류", ("DYN_OPENAPI_EXPOSED",)))
            else:
                logs.append(self._audit(response, "API 문서", "pass", "200 응답이 실제 openapi/swagger JSON 구조인지 확인", "상태가 200이어도 실제 OpenAPI 구조가 아니거나 접근되지 않음"))

        if response.probe_path.endswith(".map") and response.method == "GET":
            if "DYN_SOURCE_MAP_ACCESSIBLE" in by_rule:
                logs.append(self._audit(response, "소스맵", "finding", "200 응답이 실제 source map 구조(version/sources/mappings)인지 확인", "source map 구조가 보여 공개 소스맵으로 분류", ("DYN_SOURCE_MAP_ACCESSIBLE",)))
            else:
                logs.append(self._audit(response, "소스맵", "pass", "200 응답이 실제 source map 구조(version/sources/mappings)인지 확인", "상태가 200이어도 실제 source map 구조가 아니거나 접근되지 않음"))

        if response.method == "OPTIONS":
            cors_rules = tuple(
                rule
                for rule in (
                    "DYN_CORS_WILDCARD_CREDENTIALS",
                    "DYN_CORS_ORIGIN_REFLECTION_CREDENTIALS",
                    "DYN_CORS_ORIGIN_REFLECTION",
                    "DYN_CORS_NULL_ORIGIN",
                    "DYN_CORS_WILDCARD",
                )
                if rule in by_rule
            )
            if cors_rules:
                logs.append(self._audit(response, "CORS", "finding", "OPTIONS 응답의 Access-Control-Allow-Origin/Credentials 확인", "CORS 허용 범위가 넓어 위험 신호로 분류", cors_rules))
            else:
                logs.append(self._audit(response, "CORS", "pass", "OPTIONS 응답의 Access-Control-Allow-Origin/Credentials 확인", "wildcard credential 또는 wildcard origin 위험 신호 없음"))

        debug_rules = tuple(rule for rule in ("DYN_DEBUG_ERROR_LEAK", "DYN_DIRECTORY_LISTING") if rule in by_rule)
        if debug_rules:
            logs.append(self._audit(response, "디버그/목록", "finding", "Traceback, stack trace, directory listing 단서 확인", _finding_evidence(findings, set(debug_rules)), debug_rules))
        elif response.method == "GET":
            logs.append(self._audit(response, "디버그/목록", "pass", "Traceback, stack trace, directory listing 단서 확인", "디버그 에러나 디렉터리 목록 단서 없음"))

        if response.probe_path in DEFAULT_ACTIVE_DEEP_PATHS and response.method == "GET":
            deep_rules = tuple(
                rule
                for rule in (
                    "DYN_EXPOSED_ENV_FILE",
                    "DYN_EXPOSED_GIT_CONFIG",
                    "DYN_EXPOSED_BACKUP_OR_DUMP",
                    "DYN_PUBLIC_DEBUG_ENDPOINT",
                )
                if rule in by_rule
            )
            if deep_rules:
                logs.append(self._audit(response, "심화 노출 점검", "finding", "대표 민감 경로가 실제 민감 파일/디버그 구조를 반환하는지 확인", _finding_evidence(findings, set(deep_rules)), deep_rules))
            else:
                logs.append(self._audit(response, "심화 노출 점검", "pass", "대표 민감 경로가 실제 민감 파일/디버그 구조를 반환하는지 확인", "404/403/로그인 화면/SPA shell이거나 민감 구조 단서 없음"))

        return logs

    def _audit(
        self,
        response: HttpResponseSummary,
        check: str,
        result: str,
        looked_for: str,
        outcome: str,
        rule_ids: tuple[str, ...] = (),
        *,
        coverage_complete: bool = True,
    ) -> ProbeAuditLog:
        return ProbeAuditLog(
            check=check,
            result=result,
            method=response.method,
            url=_redacted_probe_url(response.url),
            status=response.status if coverage_complete else None,
            probe_path=_redacted_probe_path(response.probe_path or urllib.parse.urlparse(response.url).path),
            content_type=_redacted_content_type(response.headers.get("content-type", "")),
            looked_for=looked_for,
            outcome=outcome,
            rule_ids=rule_ids,
            response_hash=_response_evidence_hash(response) if coverage_complete else "",
            response_class=_dynamic_response_class(response) if coverage_complete else "incomplete",
            auth_wall=_looks_like_auth_wall_response(response) if coverage_complete else False,
            private_data_signal=bool(
                set(rule_ids)
                & {
                    "DYN_RESPONSE_SECRET_LEAK",
                    "DYN_RESPONSE_PII_LEAK",
                    "DYN_UNAUTH_ADMIN_ACCESS",
                }
            ),
            authenticated=response.authenticated,
            path_source=response.path_source,
            probe_path_ref=evidence_hash(response.probe_path or urllib.parse.urlparse(response.url).path),
            identity_assertion_match=response.identity_assertion_match if coverage_complete else False,
        )

    def _admin_route_finding(self, response: HttpResponseSummary) -> Finding | None:
        body = response.body_sample
        if _looks_like_login_or_auth_wall(body):
            return None
        if _looks_like_spa_shell(body) and not _looks_like_admin_console(body):
            return None
        if _looks_like_admin_console(body):
            return self._finding(
                "DYN_UNAUTH_ADMIN_ACCESS",
                "critical",
                "high",
                "Admin functionality reachable without auth",
                response,
                "GET /admin returned 200 and the response contains admin-console indicators.",
                "Protect admin routes with server-side authentication and authorization.",
            )
        return self._finding(
            "DYN_ADMIN_ROUTE_REVIEW_REQUIRED",
            "info",
            "low",
            "Admin-looking route returned 200",
            response,
            "GET /admin returned 200, but the body did not contain clear admin functionality indicators.",
            "Open the route manually and confirm it is only a login page or inert SPA shell.",
        )

    def _sensitive_body_findings(self, response: HttpResponseSummary) -> list[Finding]:
        if not response.body_sample:
            return []
        findings: list[Finding] = []
        is_error_response = response.status is not None and response.status >= 400
        if is_error_response:
            secret_rule_ids = _dynamic_secret_rule_ids(response, self.secret_detector.scan_text(response.body_sample, response.url))
            if secret_rule_ids:
                findings.append(
                    self._finding(
                        "DYN_RESPONSE_SECRET_LEAK",
                        "critical",
                        "high",
                        "Dynamic error response contains secret-like data",
                        response,
                        "Error response body sample matched secret indicators: " + ", ".join(secret_rule_ids[:8]),
                        "Remove secrets from error responses, rotate exposed credentials if real, and verify the endpoint after redeploy.",
                        scope=_secret_indicator_scope(secret_rule_ids),
                    )
                )
        else:
            secret_rule_ids = _dynamic_secret_rule_ids(response, self.secret_detector.scan_text(response.body_sample, response.url))
        pii_findings, pii_entities = self.pii_detector.scan_text(response.body_sample, response.url)
        pii_signal = _classify_dynamic_pii_signal(response, pii_entities)
        if secret_rule_ids and not is_error_response:
            findings.append(
                self._finding(
                    "DYN_RESPONSE_SECRET_LEAK",
                    "critical",
                    "high",
                    "Dynamic response contains secret-like data",
                    response,
                    "Response body sample matched secret indicators: " + ", ".join(secret_rule_ids[:8]),
                    "Remove secrets from API responses, rotate exposed credentials if real, and verify the endpoint after redeploy.",
                    scope=_secret_indicator_scope(secret_rule_ids),
                )
            )
        if pii_signal and pii_signal.kind == "leak":
            findings.append(
                self._finding(
                    "DYN_RESPONSE_PII_LEAK",
                    pii_signal.severity,
                    pii_signal.confidence,
                    "Dynamic error response contains personal data" if is_error_response else pii_signal.title,
                    response,
                    pii_signal.evidence,
                    pii_signal.recommendation,
                    scope=pii_signal.subtype,
                )
            )
        elif pii_signal and pii_signal.kind == "review":
            findings.append(
                self._finding(
                    "DYN_RESPONSE_PII_REVIEW",
                    pii_signal.severity,
                    pii_signal.confidence,
                    pii_signal.title,
                    response,
                    pii_signal.evidence,
                    pii_signal.recommendation,
                    scope=pii_signal.subtype,
                )
            )
        return findings

    def _deep_exposure_findings(self, response: HttpResponseSummary) -> list[Finding]:
        if response.method != "GET" or response.status != 200 or response.probe_path not in DEFAULT_ACTIVE_DEEP_PATHS:
            return []
        path = response.probe_path.lower()
        body = response.body_sample
        findings: list[Finding] = []
        if path.endswith("/.env") and _looks_like_env_file(body):
            findings.append(
                self._finding(
                    "DYN_EXPOSED_ENV_FILE",
                    "critical",
                    "high",
                    "Environment file exposed",
                    response,
                    "A known environment-file path returned key=value secret/config structure.",
                    "Remove the file from public web roots, rotate exposed values if real, and add deny rules for dotfiles.",
                )
            )
        if path.endswith("/.git/config") and _looks_like_git_config(body):
            findings.append(
                self._finding(
                    "DYN_EXPOSED_GIT_CONFIG",
                    "high",
                    "high",
                    "Git config exposed",
                    response,
                    "A .git/config path returned Git repository configuration structure.",
                    "Block access to .git directories and redeploy without repository metadata.",
                )
            )
        if path.endswith((".sql", ".zip")) and _looks_like_backup_or_dump(path, body):
            findings.append(
                self._finding(
                    "DYN_EXPOSED_BACKUP_OR_DUMP",
                    "critical",
                    "high",
                    "Backup or database dump exposed",
                    response,
                    "A common backup/dump path returned archive or SQL dump indicators.",
                    "Move backups outside public web roots, revoke public access, and rotate secrets found in dumps if real.",
                )
            )
        if path in {"/server-status", "/phpinfo.php", "/actuator/env", "/debug", "/debug/vars"} and _looks_like_public_debug_endpoint(path, body):
            findings.append(
                self._finding(
                    "DYN_PUBLIC_DEBUG_ENDPOINT",
                    "high",
                    "medium",
                    "Debug or runtime endpoint exposed",
                    response,
                    "A known debug/runtime path returned framework, environment, or server-status indicators.",
                    "Disable production debug endpoints or restrict them to private networks and authenticated operators.",
                )
            )
        return findings

    def _probe_budget_finding(self, reason: str, request_count: int, body_bytes: int, elapsed_seconds: float) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_PROBE_BUDGET_EXCEEDED",
            severity="high",
            confidence="high",
            title="Dynamic probe stopped at its aggregate resource budget",
            evidence=(
                f"reason={reason} request_count={request_count} body_bytes={body_bytes} "
                f"elapsed_ms={int(elapsed_seconds * 1000)} raw_returned=false"
            ),
            why_it_matters="A partial dynamic review must not be mistaken for complete site or API coverage.",
            recommendation="Reduce declared endpoint scope or raise the reviewed local budget explicitly, then rerun the same Guardian gate.",
            audit_depth=4,
            inspected_scope="Requests completed before the aggregate request, body-byte, or elapsed-time limit were analyzed immediately and released from memory.",
            not_inspected="Paths after the aggregate budget was reached were not requested.",
        )

    def _probe_incomplete_finding(self, error_request_count: int, request_count: int) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_PROBE_INCOMPLETE",
            severity="high",
            confidence="high",
            title="Dynamic probe did not inspect every requested response",
            evidence=(
                f"detector_subtype=dynamic_probe_incomplete request_count={request_count} "
                f"error_request_count={error_request_count} raw_returned=false"
            ),
            why_it_matters="Connection, TLS, timeout, or response-body failures leave site and API behavior unreviewed.",
            recommendation="Restore target availability or narrow the authorized scope, then rerun until error_request_count is zero.",
            audit_depth=4,
            inspected_scope="Every attempted request produced a bounded audit observation; incomplete responses were counted without returning raw network errors.",
            not_inspected="Responses associated with the counted request errors were not fully inspected and the release review must remain on hold.",
        )

    def _finding(self, rule_id: str, severity: str, confidence: str, title: str, response: HttpResponseSummary, evidence: str, recommendation: str, scope: str | None = None) -> Finding:
        privacy_meta = metadata_for_rule(rule_id, audit_depth=3 if rule_id.startswith("DYN_RESPONSE_PII") else None)
        response_hash = _response_evidence_hash(response)
        signal_location = _dynamic_signal_location(rule_id)
        redacted_fingerprint = evidence_hash(
            "|".join((rule_id, response.method, str(response.status), response.probe_path, signal_location, response_hash, str(scope or "")))
        )
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id=rule_id,
            severity=severity,
            confidence=confidence,
            title=title,
            url=_redacted_probe_url(response.url),
            method=response.method,
            status=response.status,
            scope=scope,
            evidence=(
                f"detector_subtype={rule_id.lower()} signal_location={signal_location} "
                f"response_hash={response_hash} redacted_fingerprint={redacted_fingerprint} "
                f"scheme={evidence_hash_scheme()} raw_returned=false detail={evidence}"
            ),
            why_it_matters="The running application exposed risky behavior to a bounded read-only probe.",
            recommendation=recommendation,
            privacy_class=str(privacy_meta["privacy_class"]) if privacy_meta else None,
            pipc_basis=str(privacy_meta["pipc_basis"]) if privacy_meta else None,
            audit_depth=int(privacy_meta["audit_depth"]) if privacy_meta else 1,
            inspected_scope=_inspected_scope_for_response(response),
            not_inspected="로그인 후 화면, 데이터 변경 요청, 다른 origin, 서버 내부 DB/로그 보존 상태는 이 동적 요청만으로 확인하지 않습니다.",
        )


def _response_evidence_hash(response: HttpResponseSummary) -> str:
    volatile_headers = {"date", "x-request-id", "x-correlation-id", "traceparent", "tracestate", "server-timing", "cf-ray"}
    stable_headers: list[str] = []
    for name, value in sorted(response.headers.items()):
        normalized_name = name.lower()
        if normalized_name in volatile_headers:
            continue
        normalized_value = _redacted_cookie_header(value) if normalized_name == "set-cookie" else value
        stable_headers.append(f"{normalized_name}:{normalized_value}")
    headers = "\n".join(stable_headers)
    body_digest = response.body_sha256 or hashlib.sha256(response.body_sample.encode("utf-8")).hexdigest()
    material = "\n".join((response.method, str(response.status), response.probe_path, headers, body_digest))
    return evidence_hash(material)


def _redacted_cookie_header(value: str) -> str:
    cookies: list[str] = []
    for cookie in str(value).split("\n"):
        parts = [part.strip() for part in cookie.split(";") if part.strip()]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0].strip().lower()
        attributes = sorted(part.lower() for part in parts[1:])
        cookies.append(";".join([f"{name}=<redacted>", *attributes]))
    return "\n".join(sorted(cookies))


def _dynamic_signal_location(rule_id: str) -> str:
    if rule_id in {
        "DYN_REDIRECT_TO_DISALLOWED_HOST",
        "DYN_SENSITIVE_RESPONSE_CACHE_POLICY_WEAK",
        "DYN_CORS_WILDCARD_CREDENTIALS",
        "DYN_CORS_ORIGIN_REFLECTION_CREDENTIALS",
        "DYN_CORS_ORIGIN_REFLECTION",
        "DYN_CORS_NULL_ORIGIN",
        "DYN_CORS_WILDCARD",
        "DYN_SESSION_COOKIE_FLAG_WEAK",
        "DYN_SECURITY_HEADERS_MISSING",
        "DYN_HSTS_MISSING",
    }:
        return "response_header"
    if rule_id in {"DYN_UNAUTH_ADMIN_ACCESS", "DYN_ADMIN_ROUTE_REVIEW_REQUIRED", "DYN_UNAUTH_API_JSON", "DYN_PUBLIC_API_JSON_REVIEW"}:
        return "status_and_body"
    return "response_body"


def _inspected_scope_for_response(response: HttpResponseSummary) -> str:
    path = _redacted_probe_path(response.probe_path or urllib.parse.urlparse(response.url).path)
    if response.method == "OPTIONS":
        return f"OPTIONS {path} 응답 헤더에서 CORS 관련 항목을 확인했습니다. 응답 원문은 저장하지 않습니다."
    if response.body_truncated:
        return f"{response.method} {path} 응답 본문/헤더를 안전 한도까지 검사했고, 초과분은 저장하거나 표시하지 않았습니다."
    return f"{response.method} {path} 응답 본문/헤더를 검사했고, 원문 값은 저장하지 않았습니다."


def _session_cookie_flag_gap(headers: dict[str, str]) -> list[str]:
    raw = str(headers.get("set-cookie", ""))
    if not raw:
        return []
    gaps: set[str] = set()
    for cookie in raw.split("\n"):
        parts = [part.strip() for part in cookie.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip().lower()
        if "csrf" in cookie_name or "xsrf" in cookie_name:
            continue
        if not re.search(r"(?:^|[_.-])(?:session|auth|access[_-]?token|refresh[_-]?token|jwt|sid|connect\.sid|next-auth|supabase-auth)(?:$|[_.-])", cookie_name):
            continue
        attributes = {part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip().lower() if "=" in part else "" for part in parts[1:]}
        if "secure" not in attributes:
            gaps.add("secure")
        if "httponly" not in attributes:
            gaps.add("httponly")
        if "samesite" not in attributes:
            gaps.add("samesite")
        elif attributes["samesite"] == "none" and "secure" not in attributes:
            gaps.add("secure_for_samesite_none")
    return sorted(gaps)


def _private_api_json_signal(body: str) -> bool:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, TypeError, RecursionError):
        return False
    private_keys = {
        "users",
        "customers",
        "members",
        "patients",
        "userid",
        "customerid",
        "memberid",
        "patientid",
        "accountid",
        "ownerid",
        "tenantid",
        "orderid",
        "paymentid",
        "residentregistrationnumber",
        "rrn",
        "diagnosis",
        "medicalinfo",
        "password",
        "accesstoken",
        "refreshtoken",
        "secret",
        "role",
        "permissions",
    }
    stack = [payload]
    visited = 0
    while stack and visited < 2000:
        current = stack.pop()
        visited += 1
        if isinstance(current, dict):
            for key, value in current.items():
                normalized = "".join(character.lower() for character in str(key) if character.isalnum())
                if normalized in private_keys:
                    return True
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current[:2000 - visited])
    return False


def _sensitive_cache_policy_present(headers: dict[str, str]) -> bool:
    directives = {
        item.split("=", 1)[0].strip().lower()
        for item in str(headers.get("cache-control", "")).split(",")
        if item.strip()
    }
    return bool(directives & {"no-store", "private"})


def _normalized_response_headers(headers) -> dict[str, str]:  # type: ignore[no-untyped-def]
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        cookies = [str(value) for value in (get_all("Set-Cookie") or []) if value is not None]
        if cookies:
            normalized["set-cookie"] = "\n".join(cookies)
    return normalized


def _looks_like_debug_error(body: str) -> bool:
    sample = body[:262144]
    strong_patterns = [
        "Traceback (most recent call last)",
        "Exception in thread",
        "PrismaClientKnownRequestError",
        "PrismaClientInitializationError",
        "SQL syntax",
        "Fatal error:",
        "Uncaught exception",
        "org.springframework.web",
        "werkzeug.debug",
    ]
    lower = sample.lower()
    if any(pattern.lower() in lower for pattern in strong_patterns):
        return True
    if re.search(r'(?m)^\s*File "[^"]+", line \d+, in ', sample):
        return True
    js_error = re.search(r"\b(?:ReferenceError|TypeError|SyntaxError|RangeError):\s+[^\n\r<]{1,240}", sample)
    js_frames = re.findall(r"(?m)^\s*at\s+(?:[A-Za-z_$][\w$]*\.|Object\.|[A-Za-z_$][\w$]*\s*\(|[^\n(]+\()", sample)
    return bool(js_error and len(js_frames) >= 2)


def _looks_like_login_or_auth_wall(body: str) -> bool:
    lower = body.lower()
    auth_terms = [
        "login",
        "log in",
        "sign in",
        "signin",
        "password",
        "비밀번호",
        "로그인",
        "인증",
        "unauthorized",
        "forbidden",
        "권한",
    ]
    form_terms = ["<form", "type=\"password\"", "type='password'", "csrf", "otp", "2fa"]
    return any(term in lower for term in auth_terms) and (any(term in lower for term in form_terms) or len(body) < 12000)


def _looks_like_spa_shell(body: str) -> bool:
    lower = body.lower()
    if "<html" not in lower:
        return False
    shell_terms = [
        'id="root"',
        "id='root'",
        'id="__next"',
        "id='__next'",
        "vite",
        "_next/static",
        "react",
        "vue",
        "ng-version",
    ]
    admin_terms = _admin_indicator_count(body)
    return any(term in lower for term in shell_terms) and admin_terms < 2


def _looks_like_admin_console(body: str) -> bool:
    return _admin_indicator_count(body) >= 2


def _admin_indicator_count(body: str) -> int:
    lower = body.lower()
    indicators = [
        "admin dashboard",
        "administrator",
        "user management",
        "users table",
        "delete user",
        "role management",
        "system settings",
        "관리자",
        "관리자 대시보드",
        "회원관리",
        "사용자 관리",
        "권한 관리",
        "설정 변경",
        "삭제",
        "차단",
        "승인",
    ]
    return sum(1 for indicator in indicators if indicator in lower)


def _classify_dynamic_pii_signal(response: HttpResponseSummary, entities: list[Entity]) -> DynamicPiiSignal | None:
    if not entities:
        return None
    content_type = response.headers.get("content-type", "").lower()
    body_start = response.body_sample.lstrip()[:128]
    is_html = "html" in content_type or body_start.lower().startswith("<!doctype html") or body_start.lower().startswith("<html")
    is_jsonish = "json" in content_type or body_start.startswith("{") or body_start.startswith("[")
    counts = Counter(entity.label for entity in entities)
    labels = set(counts)

    strong_counts = _dynamic_strong_identifier_counts(entities, is_html=is_html, body=response.body_sample)
    if strong_counts:
        return DynamicPiiSignal(
            kind="leak",
            severity="high",
            confidence="high",
            title="Dynamic response contains strong personal identifiers",
            evidence="Strong identifier tier detected: " + _format_label_counts(strong_counts, set(strong_counts)),
            recommendation="Require authentication, remove these identifiers from unauthenticated responses, and verify the endpoint after redeploy.",
            subtype="strong_identifier_tier_detected",
        )

    if is_html:
        return None

    linked_identifier_labels = {
        "PHONE",
        "EMAIL",
        "ADDRESS",
        "BIRTHDATE",
        "ACCOUNT_ID",
        "ORDER_ID",
        "MEDICAL_INFO",
        "SENSITIVE_INFO",
        "VEHICLE_NUMBER",
        "PATIENT_ID",
        "DEVICE_ID",
    }
    contact_labels = {"PHONE", "EMAIL", "ADDRESS", "BIRTHDATE"}
    record_labels = {"PERSON", "ACCOUNT_ID", "ORDER_ID", "MEDICAL_INFO", "SENSITIVE_INFO", "VEHICLE_NUMBER", "PATIENT_ID", "DEVICE_ID"} | contact_labels
    record_count = sum(counts[label] for label in record_labels)
    has_person_link = counts["PERSON"] > 0 and any(counts[label] > 0 for label in linked_identifier_labels)
    has_account_contact_link = (counts["ACCOUNT_ID"] > 0 or counts["ORDER_ID"] > 0) and any(counts[label] > 0 for label in {"PHONE", "EMAIL", "ADDRESS"})
    has_bulk_person_contact = counts["PERSON"] >= 3 and sum(counts[label] for label in contact_labels) >= 3
    has_bulk_contact_list = sum(counts[label] for label in {"EMAIL", "PHONE"}) >= 8 or record_count >= 12

    if is_jsonish and (has_bulk_person_contact or has_bulk_contact_list):
        return DynamicPiiSignal(
            kind="leak",
            severity="high",
            confidence="high",
            title="Dynamic response contains a bulk personal-data cluster",
            evidence="Bulk record tier detected in response: " + _format_label_counts(counts, record_labels),
            recommendation="Require authentication for this endpoint, paginate/minimize fields, and mask contact fields unless the data is intentionally public.",
            subtype="bulk_record_tier_detected",
        )

    if is_jsonish and (has_person_link or has_account_contact_link):
        return DynamicPiiSignal(
            kind="leak",
            severity="high",
            confidence="medium",
            title="Dynamic response contains linked personal data",
            evidence="Linked record tier detected: " + _format_label_counts(counts, record_labels),
            recommendation="Confirm whether this is a real user/customer record. If yes, require authentication and remove unnecessary fields from the response.",
            subtype="linked_record_tier_detected",
        )

    contact_count = sum(counts[label] for label in contact_labels)
    if is_jsonish and contact_count >= 3:
        return DynamicPiiSignal(
            kind="review",
            severity="info",
            confidence="low",
            title="Dynamic response contains a contact-data cluster",
            evidence="Contact-cluster review tier detected: " + _format_label_counts(counts, contact_labels),
            recommendation="If these are public company contact channels, no code fix is needed. If they belong to users/customers, move them behind authentication or mask them.",
            subtype="contact_cluster_review_tier",
        )

    return None


def _dynamic_secret_rule_ids(response: HttpResponseSummary, findings: list[Finding]) -> list[str]:
    content_type = response.headers.get("content-type", "").lower()
    is_html = "html" in content_type or _looks_like_html(response.body_sample)
    rule_ids = {finding.rule_id for finding in findings}
    if is_html:
        rule_ids.discard("SECRET_JWT")
    return sorted(rule_ids)


def _secret_indicator_scope(rule_ids: list[str]) -> str:
    allowed = {
        "SECRET_PRIVATE_KEY",
        "SECRET_GITHUB_PAT",
        "SECRET_AWS_ACCESS_KEY",
        "SECRET_JWT",
        "SECRET_DB_URL",
        "SECRET_OPENAI_STYLE_KEY",
        "SECRET_WEBHOOK_URL",
    }
    for rule_id in rule_ids:
        if rule_id in allowed:
            return f"secret_indicator:{rule_id}"
    return "secret_indicator"


def _dynamic_strong_identifier_counts(entities: list[Entity], is_html: bool, body: str) -> Counter[str]:
    all_strong = {
        "RRN",
        "RRN_VALID",
        "FRN",
        "PASSPORT",
        "DRIVER_LICENSE",
        "PERSONAL_CUSTOMS_CODE",
        "CREDIT_CARD",
        "BANK_ACCOUNT",
        "CI",
        "DI",
        "HEALTH_INSURANCE_ID",
    }
    html_strong = {
        "RRN_VALID",
        "DRIVER_LICENSE",
        "CI",
        "DI",
        "HEALTH_INSURANCE_ID",
    }
    if _html_credit_card_field_present(body):
        html_strong.add("CREDIT_CARD")
    counts: Counter[str] = Counter()
    for entity in entities:
        if is_html:
            if entity.label in html_strong:
                counts[entity.label] += 1
            continue
        if entity.label in all_strong:
            counts[entity.label] += 1
    return counts


def _html_credit_card_field_present(body: str) -> bool:
    if not _looks_like_html(body):
        return False
    return bool(
        re.search(
            r"(?is)(?:credit[_ -]?card|card[_ -]?(?:no|number)|카드\s*번호|신용\s*카드)[^<\n\r]{0,48}(?:\d[ -]?){13,19}",
            body[:262144],
        )
    )


def _format_label_counts(counts: Counter[str], labels: set[str]) -> str:
    parts = [f"{label}={counts[label]}" for label in sorted(labels) if counts[label] > 0]
    return ", ".join(parts[:8]) if parts else "none"


def _selected_probe_paths(paths: list[str] | None, active_profile: str) -> list[str]:
    if paths is not None:
        selected = list(paths)
    else:
        selected = list(DEFAULT_PATHS)
        if active_profile == "deep":
            selected.extend(DEFAULT_ACTIVE_DEEP_PATHS)
    deduped: list[str] = []
    seen: set[str] = set()
    for path in selected:
        normalized = str(path) if str(path).startswith("/") else "/" + str(path)
        if not _safe_discovered_get_path(normalized):
            raise ValueError("Probe paths must be literal bounded same-origin paths without query, fragment, traversal, or encoding.")
        if normalized not in seen:
            deduped.append(normalized)
            seen.add(normalized)
    return deduped


def _finding_evidence(findings: list[Finding], rule_ids: set[str]) -> str:
    evidence = [finding.evidence for finding in findings if finding.rule_id in rule_ids]
    return "; ".join(evidence[:3]) if evidence else "위험 신호가 발견됨"


def _is_openapi_path(path: str) -> bool:
    return path.endswith("/swagger.json") or path.endswith("/openapi.json")


def _looks_like_openapi_document(response: HttpResponseSummary) -> bool:
    body = response.body_sample.lstrip()
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        return False
    if not body.startswith("{"):
        return False
    lower = body[:8192].lower()
    return ('"openapi"' in lower or '"swagger"' in lower) and '"paths"' in lower


def _safe_openapi_get_paths(response: HttpResponseSummary, *, max_paths: int = DEFAULT_MAX_OPENAPI_DISCOVERY_PATHS) -> list[str]:
    if max_paths <= 0 or response.status != 200 or not _looks_like_openapi_document(response):
        return []
    try:
        document = json.loads(response.body_sample)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return []
    selected: list[str] = []
    for raw_path, operations in sorted(paths.items(), key=lambda item: str(item[0])):
        if len(selected) >= max_paths:
            break
        path = str(raw_path or "")
        if not isinstance(operations, dict) or not any(str(method).casefold() == "get" for method in operations):
            continue
        if not _safe_discovered_get_path(path):
            continue
        selected.append(path)
    return selected


def _safe_discovered_get_path(path: str) -> bool:
    lowered = str(path or "").casefold()
    decoded = str(path or "")
    for _ in range(3):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return (
        0 < len(path) <= 256
        and path.startswith("/")
        and not any(token in path for token in ("{", "}", "?", "#", "\\"))
        and "://" not in lowered
        and ".." not in path
        and "%" not in path
        and ".." not in decoded
        and "\\" not in decoded
        and all(ord(char) >= 32 for char in path)
    )


def _is_admin_probe_path(path: str) -> bool:
    normalized = str(path or "").casefold().rstrip("/")
    return normalized.startswith("/admin") or normalized == "/wp-admin"


def _looks_like_auth_wall_response(response: HttpResponseSummary) -> bool:
    if response.status in {401, 403}:
        return True
    location = response.headers.get("location", "").casefold()
    if response.status in {301, 302, 303, 307, 308} and re.search(r"(?:^|/)(?:login|signin|sign-in|auth)(?:[/?#]|$)", location):
        return True
    return response.status == 200 and _looks_like_login_or_auth_wall(response.body_sample)


def _dynamic_response_class(response: HttpResponseSummary) -> str:
    if response.status is None or _response_body_incomplete(response):
        return "error"
    if _looks_like_auth_wall_response(response):
        return "auth_wall"
    if response.status in {301, 302, 303, 307, 308}:
        return "redirect"
    content_type = response.headers.get("content-type", "").casefold()
    body = response.body_sample.lstrip()
    if "json" in content_type or body.startswith(("{", "[")):
        return "json"
    if "html" in content_type or _looks_like_html(body):
        return "html"
    if response.status >= 500:
        return "server_error"
    return "other"


def _looks_like_source_map(response: HttpResponseSummary) -> bool:
    body = response.body_sample.lstrip()
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        return False
    if not body.startswith("{"):
        return False
    lower = body[:8192].lower()
    return '"version"' in lower and '"sources"' in lower and '"mappings"' in lower


def _looks_like_env_file(body: str) -> bool:
    if _looks_like_html(body):
        return False
    secretish = re.compile(r"(?m)^(?:[A-Z0-9_]{3,}|[A-Za-z][A-Za-z0-9_]{2,})=(?!$).+")
    lines = secretish.findall(body[:8192])
    keywords = ("SECRET", "TOKEN", "API_KEY", "DATABASE_URL", "DB_PASSWORD", "PRIVATE_KEY", "NEXTAUTH", "JWT")
    return len(lines) >= 2 and any(keyword in body[:8192].upper() for keyword in keywords)


def _looks_like_git_config(body: str) -> bool:
    if _looks_like_html(body):
        return False
    lower = body[:8192].lower()
    return "[core]" in lower and ("repositoryformatversion" in lower or "[remote " in lower)


def _looks_like_backup_or_dump(path: str, body: str) -> bool:
    if _looks_like_html(body):
        return False
    upper = body[:8192].upper()
    if path.endswith(".zip") and body.startswith("PK"):
        return True
    return any(marker in upper for marker in ("CREATE TABLE", "INSERT INTO", "MYSQL DUMP", "POSTGRESQL DATABASE DUMP", "SQLITE FORMAT 3"))


def _looks_like_public_debug_endpoint(path: str, body: str) -> bool:
    if not body:
        return False
    lower = body[:8192].lower()
    if path == "/server-status":
        return "apache server status" in lower or ("server uptime" in lower and "total accesses" in lower)
    if path == "/phpinfo.php":
        return "phpinfo()" in lower or "php version" in lower
    if path == "/actuator/env":
        return "propertysources" in lower or "activeprofiles" in lower or "systemenvironment" in lower
    if path in {"/debug", "/debug/vars"}:
        return "goroutine" in lower or "memstats" in lower or "debug toolbar" in lower or "werkzeug" in lower
    return False


def _looks_like_html(body: str) -> bool:
    start = body.lstrip()[:128].lower()
    return start.startswith("<!doctype html") or start.startswith("<html")


def _allowed_host(hostname: str | None, allowed_hosts: set[str]) -> bool:
    return _resolved_probe_address(hostname, allowed_hosts) is not None


def _resolved_probe_address(hostname: str | None, allowed_hosts: set[str]) -> str | None:
    if hostname is None:
        return None
    host = hostname.strip("[]").rstrip(".").lower()
    normalized_allowed = {item.strip("[]").rstrip(".").lower() for item in allowed_hosts}
    if host not in normalized_allowed:
        return None
    if host == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
                for _family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError):
            return None
        if not addresses or not all(_is_public_probe_address(address) for address in addresses):
            return None
        selected = min(addresses, key=lambda address: (address.version, int(address)))
        return str(selected)
    if ip in {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}:
        return str(ip)
    return str(ip) if _is_public_probe_address(ip) else None


def _is_public_probe_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_global and not any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_reserved,
            address.is_multicast,
            address.is_unspecified,
        )
    )


def _pin_loopback_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip("[]").lower()
    if host != "localhost":
        return url
    netloc = "127.0.0.1"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))


def _probe_headers(session_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"User-Agent": "k-guard-mcp/0.1"}
    if not session_headers:
        return headers
    allowed = {"authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "x-session-token"}
    for key, value in session_headers.items():
        normalized = str(key).strip()
        value_text = str(value)
        if not normalized or "\r" in normalized or "\n" in normalized or "\r" in value_text or "\n" in value_text:
            continue
        if normalized.casefold() not in allowed:
            continue
        headers[normalized] = value_text
    return headers


def _session_headers_indicate_authentication(session_headers: dict[str, str] | None) -> bool:
    if not session_headers:
        return False
    exact_names = {"authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "x-session-token"}
    for raw_name, raw_value in session_headers.items():
        name = str(raw_name).strip().lower()
        if not name or not str(raw_value).strip() or name == "set-cookie":
            continue
        if name in exact_names:
            return True
    return False


def _redacted_probe_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urllib.parse.urlunparse((parsed.scheme, f"{host}{port}", _redacted_probe_path(parsed.path or "/"), "", "", ""))
    except (TypeError, ValueError):
        return ""


def _normalized_origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold()
        if not scheme or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)
        return scheme, host, port
    except (TypeError, ValueError):
        return None


def _redacted_probe_path(path: str) -> str:
    normalized = str(path or "/").split("?", 1)[0].split("#", 1)[0] or "/"
    known = {*DEFAULT_PATHS, *DEFAULT_ACTIVE_DEEP_PATHS}
    if normalized in known:
        return normalized
    return f"/<path-ref:{evidence_hash(normalized)}>"


def _redacted_content_type(value: str) -> str:
    media_type = str(value or "").split(";", 1)[0].strip().casefold()
    if re.fullmatch(
        r"(?:application/(?:json|problem\+json|javascript|xml|octet-stream|pdf|zip|wasm)|"
        r"text/(?:html|plain|css|javascript|xml)|image/(?:png|jpeg|gif|webp|svg\+xml))",
        media_type,
    ):
        return media_type
    return "unknown" if not media_type else f"<content-type-ref:{evidence_hash(media_type)}>"


def _identity_assertion_matches(
    response: HttpResponseSummary,
    assertion: dict[str, object] | None,
) -> bool:
    if not assertion or _response_body_incomplete(response):
        return False
    expected_path = str(assertion.get("path") or "")
    expected_hash = str(assertion.get("expected_body_sha256") or "").casefold()
    try:
        expected_status = int(assertion.get("expected_status", 200))
    except (TypeError, ValueError):
        return False
    if (
        response.method != "GET"
        or response.probe_path != expected_path
        or response.status != expected_status
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
    ):
        return False
    return bool(response.body_sha256) and hmac.compare_digest(response.body_sha256, expected_hash)


def _read_limited_body(response, max_body_bytes: int, deadline: float | None = None) -> tuple[str, bool, int, bool, bool, str]:  # type: ignore[no-untyped-def]
    raw = bytearray()
    deadline_exceeded = False
    while len(raw) <= max_body_bytes:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                deadline_exceeded = True
                break
            _set_response_socket_timeout(response, max(0.05, remaining))
        chunk_size = min(65536, max_body_bytes + 1 - len(raw))
        try:
            chunk = _read_response_chunk(response, chunk_size)
        except (TimeoutError, socket.timeout):
            deadline_exceeded = True
            break
        if not chunk:
            break
        raw.extend(chunk)
    truncated = len(raw) > max_body_bytes or deadline_exceeded
    inspected = bytes(raw[:max_body_bytes])
    expected_length = _response_content_length(response)
    length_mismatch = expected_length is not None and expected_length <= max_body_bytes and len(raw) < expected_length
    return (
        inspected.decode("utf-8", errors="ignore"),
        truncated,
        len(inspected),
        deadline_exceeded,
        length_mismatch,
        hashlib.sha256(inspected).hexdigest(),
    )


def _body_read_error(truncated: bool, deadline_exceeded: bool, length_mismatch: bool = False) -> str | None:
    if deadline_exceeded:
        return "response_body_deadline_exceeded"
    if truncated:
        return "response_body_truncated"
    if length_mismatch:
        return "response_content_length_mismatch"
    return None


def _response_content_length(response) -> int | None:  # type: ignore[no-untyped-def]
    headers = getattr(response, "headers", None)
    raw = headers.get("Content-Length") if headers is not None else None
    try:
        value = int(str(raw))
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _network_error_observation(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    candidates = [exc, reason]
    if any(isinstance(item, (TimeoutError, socket.timeout)) for item in candidates):
        code = "timeout"
    elif any(isinstance(item, socket.gaierror) for item in candidates):
        code = "dns_resolution_failed"
    elif any(isinstance(item, ConnectionRefusedError) or getattr(item, "errno", None) in {61, 111, 10061} for item in candidates):
        code = "connection_refused"
    elif any(isinstance(item, ssl.SSLError) for item in candidates):
        code = "tls_failed"
    else:
        code = "network_failed"
    error_ref = evidence_hash(f"{type(exc).__name__}:{exc}")
    return f"request_error={code} error_ref={error_ref} scheme={evidence_hash_scheme()} raw_returned=false"


def _response_body_incomplete(response: HttpResponseSummary) -> bool:
    return response.body_truncated or any(
        marker in str(response.error or "")
        for marker in (
            "response_body_deadline_exceeded",
            "response_body_truncated",
            "response_content_length_mismatch",
        )
    )


def _read_response_chunk(response, size: int) -> bytes:  # type: ignore[no-untyped-def]
    for candidate in (response, getattr(response, "fp", None)):
        reader = getattr(candidate, "read1", None)
        if callable(reader):
            return reader(size)
    return response.read(min(size, 8192))


def _set_response_socket_timeout(response, timeout: float) -> None:  # type: ignore[no-untyped-def]
    queue = [response]
    seen: set[int] = set()
    for _ in range(12):
        if not queue:
            return
        current = queue.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        for socket_name in ("_sock", "sock"):
            socket_object = getattr(current, socket_name, None)
            setter = getattr(socket_object, "settimeout", None)
            if callable(setter):
                try:
                    setter(timeout)
                except OSError:
                    return
                return
        for child_name in ("fp", "raw", "_fp"):
            child = getattr(current, child_name, None)
            if child is not None:
                queue.append(child)


def _configured_max_body_bytes() -> int:
    raw = os.environ.get(MAX_BODY_BYTES_ENV)
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return min(MAX_BODY_BYTES_LIMIT, max(MIN_BODY_BYTES_LIMIT, value))
