from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from k_guard_mcp.dashboard_ui import render_dashboard, render_scope
from k_guard_mcp.dynamic import ALLOWED_HOSTS, DEFAULT_ACTIVE_DEEP_PATHS, DEFAULT_PATHS, SafeHttpProbe, _allowed_host
from k_guard_mcp.models import ScanResult


ALLOWLIST_ENV = "K_GUARD_DASHBOARD_ALLOWED_HOSTS"
VERIFY_TOKEN_ENV = "K_GUARD_DASHBOARD_VERIFY_TOKEN"
VERIFY_PATH = "/.well-known/k-guard-mcp-verify.txt"
SESSION_VERIFY_TOKEN = secrets.token_urlsafe(18)
DASHBOARD_CSRF_TOKEN = secrets.token_urlsafe(32)

CHECKS = [
    {
        "name": "보안 헤더",
        "rule_ids": ["DYN_SECURITY_HEADERS_MISSING"],
        "description": "브라우저가 XSS, iframe 삽입, MIME sniffing을 막도록 돕는 기본 헤더가 빠졌는지 봅니다.",
    },
    {
        "name": "CORS 정책",
        "rule_ids": ["DYN_CORS_WILDCARD", "DYN_CORS_WILDCARD_CREDENTIALS"],
        "description": "다른 사이트에서 내 API를 마음대로 읽을 수 있게 열려 있는지 봅니다.",
    },
    {
        "name": "로그인 없는 관리자/API",
        "rule_ids": ["DYN_UNAUTH_ADMIN_ACCESS", "DYN_ADMIN_ROUTE_REVIEW_REQUIRED", "DYN_UNAUTH_API_JSON"],
        "description": "/admin, /api, /api/users가 로그인 없이 실제 기능이나 데이터를 주는지 봅니다. 로그인 화면/SPA만으로는 큰 위험으로 올리지 않습니다.",
    },
    {
        "name": "응답 안의 개인정보/키",
        "rule_ids": ["DYN_RESPONSE_PII_LEAK", "DYN_RESPONSE_PII_REVIEW", "DYN_RESPONSE_SECRET_LEAK"],
        "description": "응답 본문에서 강한 식별자, 이름+연락처 레코드, 연락처 묶음, API key를 봅니다. 대표 이름/안내 전화/공개 이메일 하나둘은 표시하지 않습니다.",
    },
    {
        "name": "API 문서와 소스맵",
        "rule_ids": ["DYN_OPENAPI_EXPOSED", "DYN_SOURCE_MAP_ACCESSIBLE"],
        "description": "swagger/openapi 문서나 프론트엔드 source map이 공개되어 있는지 봅니다.",
    },
    {
        "name": "디버그/목록 노출",
        "rule_ids": ["DYN_DEBUG_ERROR_LEAK", "DYN_DIRECTORY_LISTING"],
        "description": "Traceback, stack trace, directory listing처럼 내부 정보가 보이는지 봅니다.",
    },
    {
        "name": "심화 노출 점검",
        "rule_ids": ["DYN_EXPOSED_ENV_FILE", "DYN_EXPOSED_GIT_CONFIG", "DYN_EXPOSED_BACKUP_OR_DUMP", "DYN_PUBLIC_DEBUG_ENDPOINT"],
        "description": "권한 있는 심화 모드에서 .env, .git/config, backup.sql, phpinfo, server-status, actuator/env 같은 대표 개구멍을 작은 고정 목록으로 확인합니다.",
    },
    {
        "name": "리다이렉트",
        "rule_ids": ["DYN_REDIRECT_TO_DISALLOWED_HOST"],
        "description": "입력한 사이트 밖으로 튀는 리다이렉트는 따라가지 않고, 결과에 경계 이탈 신호로 기록합니다.",
    },
]

NON_GOALS = [
    "로그인 시도, 비밀번호 대입, 계정 공격은 하지 않습니다.",
    "폼 제출, 파일 업로드, 데이터 변경 요청은 하지 않습니다.",
    "기본 모드는 fuzzing, 공격 payload, 경로 무차별 대입, 전체 크롤링을 하지 않습니다.",
    "심화 모드는 작은 고정 목록의 공개 민감 경로만 GET으로 확인합니다. 대량 사전 대입이나 exploit chain은 실행하지 않습니다.",
    "입력한 사이트 밖으로 넘어가지 않습니다. 다른 호스트 redirect는 따라가지 않습니다.",
    "보증이나 인증서가 아닙니다. 사람이 확인할 수 있게 위험 신호를 정리합니다.",
]

RULE_GUIDANCE = {
    "DYN_SECURITY_HEADERS_MISSING": {
        "ko_title": "보안 헤더가 빠져 있습니다",
        "easy": "브라우저에게 '이 사이트를 더 안전하게 다뤄라'고 알려주는 기본 안전벨트가 일부 없습니다.",
        "fix_steps": [
            "Next.js라면 next.config.js의 headers()에 Content-Security-Policy와 X-Frame-Options 또는 frame-ancestors를 추가합니다.",
            "Nginx/Cloudflare/Vercel 같은 앞단에서 공통 보안 헤더를 넣어도 됩니다.",
            "먼저 report-only CSP로 배포해 깨지는 리소스가 없는지 확인한 뒤 강제 CSP로 바꿉니다.",
        ],
    },
    "DYN_CORS_WILDCARD": {
        "ko_title": "CORS가 모든 사이트에 열려 있습니다",
        "easy": "다른 웹사이트에서도 이 사이트의 응답을 읽을 수 있게 열려 있을 수 있습니다.",
        "fix_steps": [
            "Access-Control-Allow-Origin: * 대신 실제 프론트 도메인만 허용합니다.",
            "API가 공개 API가 아니라면 CORS 허용을 제거하거나 로그인된 사용자에게만 응답하게 만듭니다.",
        ],
    },
    "DYN_CORS_WILDCARD_CREDENTIALS": {
        "ko_title": "CORS wildcard와 credentials가 같이 켜져 있습니다",
        "easy": "쿠키/인증정보가 붙은 요청까지 모든 출처에 열릴 수 있는 위험한 조합입니다.",
        "fix_steps": [
            "Access-Control-Allow-Origin: *와 Access-Control-Allow-Credentials: true를 같이 쓰지 않습니다.",
            "credentials가 필요하면 허용 origin을 정확한 도메인 목록으로 제한합니다.",
        ],
    },
    "DYN_UNAUTH_ADMIN_ACCESS": {
        "ko_title": "관리자 기능이 로그인 없이 보입니다",
        "easy": "/admin 경로가 인증 없이 200 OK를 반환했고, 응답 안에 회원관리/설정/삭제 같은 관리자 기능 단서가 있습니다.",
        "fix_steps": [
            "서버 사이드 middleware에서 관리자 세션/권한을 확인합니다.",
            "프론트에서 숨기는 것만으로는 부족합니다. 서버가 직접 401/403을 반환해야 합니다.",
        ],
    },
    "DYN_ADMIN_ROUTE_REVIEW_REQUIRED": {
        "ko_title": "관리자 경로가 200이지만 확인 필요입니다",
        "easy": "/admin이 200 OK를 반환했지만, 로그인 화면이나 SPA shell일 수도 있어 강한 취약점으로 보지는 않았습니다.",
        "fix_steps": [
            "브라우저에서 /admin에 접속해 로그인 없이 회원관리/설정 변경 같은 기능이 실제 동작하는지 확인합니다.",
            "로그인 화면만 보인다면 제품 설정에서 이 항목을 무시 처리해도 됩니다.",
            "관리 기능이 보인다면 서버 middleware에서 401/403 또는 로그인 redirect를 강제합니다.",
        ],
    },
    "DYN_UNAUTH_API_JSON": {
        "ko_title": "API가 로그인 없이 JSON을 반환합니다",
        "easy": "/api 계열 경로가 인증 없이 데이터를 돌려줍니다. 공개 API라면 괜찮지만, 사용자/주문/관리 데이터면 위험합니다.",
        "fix_steps": [
            "공개 API인지 먼저 분류합니다.",
            "비공개 API라면 세션/JWT/API key 검증을 서버에서 적용합니다.",
            "필요 없는 필드는 응답에서 제거합니다.",
        ],
    },
    "DYN_RESPONSE_PII_LEAK": {
        "ko_title": "응답에 개인정보 묶음이 있습니다",
        "easy": "응답에서 주민번호/여권/면허/외국인번호, CI/DI, 건강보험번호, 환자번호, 계좌/카드 같은 강한 식별자나 이름+연락처처럼 결합된 레코드가 감지됐습니다. 이름/메일/전화가 여러 개 반복되는 묶음도 위험 신호로 봅니다. 원문 값은 표시하지 않았습니다.",
        "fix_steps": [
            "근거의 tier와 개수를 보고 단일 안내 연락처인지, 사용자/고객 레코드 묶음인지 확인합니다.",
            "사용자/고객/환자/회원 레코드라면 로그인 없는 응답에서 개인정보 필드를 제거합니다.",
            "목록 API라면 페이지네이션을 적용하고 마스킹된 값만 내려보냅니다.",
            "서버 로그와 fixture에도 실제 개인정보가 남아 있는지 같이 확인합니다.",
        ],
    },
    "DYN_RESPONSE_PII_REVIEW": {
        "ko_title": "응답에 연락처 묶음 후보가 있습니다",
        "easy": "전화번호/이메일/주소가 여러 개 보이지만 이름과 강하게 묶이진 않았습니다. 회사 안내 연락처 묶음일 수도 있어 낮은 우선순위로 표시합니다.",
        "fix_steps": [
            "근거의 EMAIL/PHONE/ADDRESS 개수를 보고 공개 안내 연락처인지 사용자/고객 연락처인지 구분합니다.",
            "공개 회사 연락처라면 수정할 필요가 없고, 제품 allowlist/무시 처리 대상으로 분리합니다.",
            "사용자/고객 연락처라면 로그인 뒤에서만 내려보내고 필요 없는 필드는 제거합니다.",
        ],
    },
    "DYN_RESPONSE_SECRET_LEAK": {
        "ko_title": "응답에 API key/secret 패턴이 있습니다",
        "easy": "응답 본문 샘플에서 API key나 token처럼 보이는 값이 감지됐습니다. 진짜라면 즉시 폐기/교체해야 합니다.",
        "fix_steps": [
            "노출된 key가 실제 key라면 바로 revoke/rotate 합니다.",
            "NEXT_PUBLIC_* 같은 클라이언트 공개 환경변수에 secret을 넣지 않습니다.",
            "서버 전용 secret manager나 서버 런타임 환경변수로 옮깁니다.",
        ],
    },
    "DYN_OPENAPI_EXPOSED": {
        "ko_title": "API 문서가 공개되어 있습니다",
        "easy": "swagger.json 또는 openapi.json이 로그인 없이 열립니다. 공격자는 API 목록과 파라미터를 쉽게 볼 수 있습니다.",
        "fix_steps": [
            "운영 환경에서는 API 문서를 끄거나 Basic Auth/사내망/VPN 뒤로 옮깁니다.",
            "문서가 필요하면 공개 가능한 endpoint와 내부 endpoint를 분리합니다.",
        ],
    },
    "DYN_SOURCE_MAP_ACCESSIBLE": {
        "ko_title": "프론트엔드 소스맵이 공개되어 있습니다",
        "easy": "source map이 열리면 압축 전 코드 구조, 파일명, 주석, 내부 경로가 보일 수 있습니다.",
        "fix_steps": [
            "Next.js/Vite/Webpack 운영 빌드에서 productionBrowserSourceMaps 또는 sourcemap 공개 설정을 끕니다.",
            "Sentry 같은 서비스에는 업로드하되 public web에서는 접근하지 못하게 합니다.",
        ],
    },
    "DYN_DEBUG_ERROR_LEAK": {
        "ko_title": "디버그 에러가 노출됩니다",
        "easy": "Traceback/stack trace 같은 내부 에러 정보가 브라우저에 보입니다.",
        "fix_steps": [
            "운영 환경에서 DEBUG=false, NODE_ENV=production을 확인합니다.",
            "예외 응답은 사용자용 짧은 메시지로 바꾸고 상세는 서버 로그에만 남깁니다.",
        ],
    },
    "DYN_DIRECTORY_LISTING": {
        "ko_title": "디렉터리 목록이 노출됩니다",
        "easy": "서버 폴더 안 파일 목록이 웹에서 보일 수 있습니다.",
        "fix_steps": [
            "Nginx autoindex off, Apache Options -Indexes처럼 directory listing을 끕니다.",
            "정적 파일 버킷이라면 public prefix를 분리하고 목록 권한을 제거합니다.",
        ],
    },
    "DYN_REDIRECT_TO_DISALLOWED_HOST": {
        "ko_title": "다른 호스트로 리다이렉트됩니다",
        "easy": "입력한 사이트 밖으로 이동하는 redirect가 발견되어 따라가지 않았습니다.",
        "fix_steps": [
            "redirect 대상이 의도된 도메인인지 확인합니다.",
            "사용자 입력으로 redirect URL을 받는다면 open redirect 방어 allowlist를 적용합니다.",
        ],
    },
    "DYN_EXPOSED_ENV_FILE": {
        "ko_title": "환경파일이 공개되어 있습니다",
        "easy": ".env 같은 환경파일 경로가 key=value 구조와 secret/API/DB 설정 단서를 돌려줍니다. 유리창 안에 집주소와 열쇠가 같이 보이는 상태에 가깝습니다.",
        "fix_steps": [
            "public web root에서 .env 파일을 제거합니다.",
            "Nginx/Apache/Cloudflare/Vercel에서 dotfile 접근을 차단합니다.",
            "실제 secret이 있었다면 즉시 revoke/rotate 합니다.",
        ],
    },
    "DYN_EXPOSED_GIT_CONFIG": {
        "ko_title": "Git 설정 디렉터리가 공개되어 있습니다",
        "easy": ".git/config가 열리면 저장소 구조와 remote 정보가 노출될 수 있고, 다른 .git 객체까지 이어질 수 있습니다.",
        "fix_steps": [
            ".git 디렉터리를 운영 배포물에서 제거합니다.",
            "웹서버에서 /.git/ 접근을 403/404로 막습니다.",
            "배포 파이프라인이 source checkout 전체를 public root에 올리지 않는지 확인합니다.",
        ],
    },
    "DYN_EXPOSED_BACKUP_OR_DUMP": {
        "ko_title": "백업 또는 DB dump 파일이 공개되어 있습니다",
        "easy": "backup.sql, dump.sql, backup.zip 같은 흔한 백업 경로가 실제 archive/SQL dump 단서를 반환했습니다.",
        "fix_steps": [
            "백업 파일을 public web root 밖으로 이동합니다.",
            "이미 노출된 dump 안에 개인정보나 secret이 있었다면 접근 로그와 키 회전을 확인합니다.",
            "백업 저장소는 별도 인증/암호화/수명 정책을 적용합니다.",
        ],
    },
    "DYN_PUBLIC_DEBUG_ENDPOINT": {
        "ko_title": "디버그/런타임 endpoint가 공개되어 있습니다",
        "easy": "phpinfo, server-status, actuator/env, debug endpoint가 운영 외부에서 보일 수 있습니다. 내부 경로, 환경, 서버 상태가 새어 나갈 수 있습니다.",
        "fix_steps": [
            "운영 환경에서 debug endpoint를 끕니다.",
            "필요한 운영 endpoint는 사내망/VPN/IP allowlist/관리자 인증 뒤로 이동합니다.",
            "actuator/env처럼 환경값을 보여주는 endpoint는 production profile에서 비활성화합니다.",
        ],
    },
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="k-guard-dashboard", description="Run the local K-Guard audit dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not _allowed_host(args.host, ALLOWED_HOSTS):
        parser.error("The audit dashboard binds to localhost/loopback only.")

    httpd = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"K-Guard dashboard listening on http://{args.host}:{httpd.server_port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "KGuardDashboard/0.1"

    def end_headers(self) -> None:
        csp = getattr(
            self,
            "_response_csp",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def log_message(self, format, *args):  # type: ignore[no-untyped-def]
        return

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._send_html(_dashboard_html())
            return
        if self.path in {"/scope", "/scope/"}:
            self._send_html(_scope_html())
            return
        if self.path == "/assets/glasses-senpai-hero.png":
            self._send_asset(Path(__file__).with_name("assets") / "glasses-senpai-hero.png", "image/png")
            return
        if self.path == "/api/checks":
            self._send_json({"checks": CHECKS, "non_goals": NON_GOALS, "active_paths": DEFAULT_PATHS, "verification": _verification_info()})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path != "/api/scan":
            self.send_response(404)
            self.end_headers()
            return
        if not self._trusted_scan_request():
            self._send_json(
                {
                    "ok": False,
                    "error": "DASHBOARD_REQUEST_REJECTED",
                    "message": "검수 요청 경계를 확인하지 못했습니다. 입력 주소와 권한 범위를 확인한 뒤 다시 시도하세요.",
                    "raw_error_returned": False,
                },
                status=403,
            )
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("invalid content length")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request payload must be an object")
            result = scan_url(
                str(payload.get("url", "")),
                _json_boolean(payload, "authorized"),
                deep_active=_json_boolean(payload, "deep_active"),
            )
            self._send_json(result, status=200 if result.get("ok") else 424)
        except Exception:
            self._send_json(
                {
                    "ok": False,
                    "error": "DASHBOARD_SCAN_FAILED",
                    "message": "검수를 완료하지 못했습니다. 입력 주소와 권한 범위를 확인한 뒤 다시 시도하세요.",
                    "raw_error_returned": False,
                },
                status=400,
            )

    def _trusted_scan_request(self) -> bool:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            return False
        token = self.headers.get("X-K-Guard-CSRF", "")
        if not token or not hmac.compare_digest(token, DASHBOARD_CSRF_TOKEN):
            return False
        fetch_site = self.headers.get("Sec-Fetch-Site", "").casefold()
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return False
        expected_port = int(self.server.server_address[1])
        if not _dashboard_authority_matches(self.headers.get("Host", ""), expected_port):
            return False
        origin = self.headers.get("Origin", "")
        if origin and not _dashboard_origin_matches(origin, expected_port):
            return False
        return True

    def _send_html(self, html: str) -> None:
        nonce = secrets.token_urlsafe(18)
        html = html.replace("__K_GUARD_CSRF__", DASHBOARD_CSRF_TOKEN)
        html = html.replace("<style>", f'<style nonce="{nonce}">').replace("<script>", f'<script nonce="{nonce}">')
        self._response_csp = (
            "default-src 'none'; "
            "base-uri 'none'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self'; "
            f"script-src 'nonce-{nonce}'; "
            f"style-src 'nonce-{nonce}'"
        )
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, value: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_asset(self, path: Path, content_type: str) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _json_boolean(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a JSON boolean")
    return value


def scan_url(raw_url: str, authorized: bool, deep_active: bool = False) -> dict[str, Any]:
    url = _normalize_url(raw_url)
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        raise ValueError("URL host is required.")
    local_target = _allowed_host(host, ALLOWED_HOSTS)
    if not local_target and not _allowed_host(host, {host}):
        raise ValueError("External target DNS must resolve only to globally routable addresses.")
    authorization = _authorization_for(url, host, local_target, authorized)
    if not authorization["allowed"]:
        raise ValueError("External targets require authorization evidence: owner attestation, allowlist, or domain proof.")

    allowed_hosts = set(ALLOWED_HOSTS)
    if authorization["allowed"]:
        allowed_hosts.add(host)
    probe = SafeHttpProbe(allowed_hosts=allowed_hosts, timeout=2.0)
    active_profile = "deep" if deep_active else "baseline"
    raw_findings, audit_log = probe.probe_with_audit(url, active_profile=active_profile)
    result = ScanResult(findings=raw_findings).finalize()
    data = result.to_dict()
    findings = [_enrich_finding(finding) for finding in data["findings"]]
    rule_ids = sorted({finding["rule_id"] for finding in findings})
    request_logs = [entry for entry in audit_log if entry.check == "HTTP 요청"]
    request_error_count = sum(1 for entry in request_logs if entry.result == "error")
    control_error_count = sum(1 for entry in audit_log if entry.result == "error" and entry.check != "HTTP 요청")
    successful_response_count = sum(1 for entry in request_logs if entry.status is not None)
    review_complete = (
        bool(request_logs)
        and request_error_count == 0
        and control_error_count == 0
        and successful_response_count > 0
    )
    return {
        "ok": review_complete,
        "review_status": "completed" if review_complete else "incomplete",
        "message": "동적 검수가 완료됐습니다." if review_complete else "요청 오류로 동적 검수를 완료하지 못했습니다. 실행 상태와 주소를 확인한 뒤 다시 시도하세요.",
        "raw_error_returned": False,
        "execution": {
            "review_complete": review_complete,
            "request_count": len(request_logs),
            "successful_response_count": successful_response_count,
            "request_error_count": request_error_count,
            "control_error_count": control_error_count,
            "raw_returned": False,
        },
        "target": {
            "url": url,
            "host": host,
            "local_target": local_target,
            "authorization_required": not local_target,
            "authorization": authorization,
            "active_profile": active_profile,
            "active_paths": DEFAULT_PATHS + (DEFAULT_ACTIVE_DEEP_PATHS if deep_active else []),
        },
        "summary": data["summary"],
        "findings": findings,
        "rule_ids": rule_ids,
        "exposure_map": _exposure_map(rule_ids, review_complete=review_complete),
        "audit_log": [entry.to_dict() for entry in audit_log],
        "checks": CHECKS,
        "non_goals": NON_GOALS,
    }


def _normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("URL is required.")
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme:
        value = "https://" + value
        parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")
    if not parsed.netloc:
        raise ValueError("URL host is required.")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not supported.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Enter the target origin only; declare review paths in Guardian public_endpoints.")
    return urllib.parse.urlunparse(parsed._replace(path=parsed.path or "/", params="", query="", fragment=""))


def _dashboard_authority_matches(authority: str, expected_port: int) -> bool:
    try:
        parsed = urllib.parse.urlparse(f"//{authority}")
        host = (parsed.hostname or "").strip("[]").casefold()
        port = parsed.port
    except ValueError:
        return False
    return bool(host) and _allowed_host(host, ALLOWED_HOSTS) and port == expected_port


def _dashboard_origin_matches(origin: str, expected_port: int) -> bool:
    try:
        parsed = urllib.parse.urlparse(origin)
        host = (parsed.hostname or "").strip("[]").casefold()
        port = parsed.port
    except ValueError:
        return False
    return parsed.scheme == "http" and bool(host) and _allowed_host(host, ALLOWED_HOSTS) and port == expected_port


def _authorization_for(url: str, host: str, local_target: bool, user_attested: bool) -> dict[str, Any]:
    if local_target:
        return {"allowed": True, "method": "local_target", "detail": "localhost/loopback target"}
    if host in _configured_allowed_hosts():
        return {"allowed": True, "method": "operator_allowlist", "detail": f"{ALLOWLIST_ENV} contains this host"}
    if user_attested and _domain_proof_present(url):
        return {"allowed": True, "method": "domain_proof", "detail": VERIFY_PATH}
    if user_attested:
        return {"allowed": True, "method": "user_attestation", "detail": "operator confirmed target authorization in the dashboard"}
    return {"allowed": False, "method": "missing", "detail": "external target has no authorization evidence"}


def _configured_allowed_hosts() -> set[str]:
    raw = os.environ.get(ALLOWLIST_ENV, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip() and item.strip() != "*"}


def _domain_proof_present(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        return False
    verify_url = urllib.parse.urlunparse(parsed._replace(path=VERIFY_PATH, params="", query="", fragment=""))
    probe = SafeHttpProbe(
        allowed_hosts={host},
        timeout=3.0,
        max_body_bytes=4096,
        max_total_body_bytes=4096,
        max_total_seconds=3.0,
        max_requests=1,
    )
    response = probe._request(
        verify_url,
        "GET",
        headers={"User-Agent": "k-guard-dashboard/0.1"},
        probe_path=VERIFY_PATH,
        max_body_bytes=4096,
        timeout=3.0,
    )
    if response.status != 200 or response.error:
        return False
    token = _verification_token()
    return f"k-guard-mcp-verify:{token}" in response.body_sample


def _verification_token() -> str:
    return os.environ.get(VERIFY_TOKEN_ENV, SESSION_VERIFY_TOKEN)


def _verification_info() -> dict[str, Any]:
    return {
        "methods": ["local_target", "operator_allowlist", "domain_proof", "user_attestation"],
        "allowlist_env": ALLOWLIST_ENV,
        "allowlist_hosts": sorted(_configured_allowed_hosts()),
        "domain_proof_path": VERIFY_PATH,
        "domain_proof_value": f"k-guard-mcp-verify:{_verification_token()}",
        "token_env": VERIFY_TOKEN_ENV,
    }


def _enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    guidance = RULE_GUIDANCE.get(str(finding.get("rule_id")), {})
    if str(finding.get("rule_id")) == "DYN_RESPONSE_PII_LEAK":
        guidance = _dynamic_pii_leak_guidance(finding)
    enriched = dict(finding)
    enriched["ko_title"] = guidance.get("ko_title", finding.get("title", "점검 항목"))
    enriched["easy_explanation"] = guidance.get("easy", finding.get("why_it_matters", "확인이 필요한 항목입니다."))
    enriched["fix_steps"] = guidance.get("fix_steps", [finding.get("recommendation", "설정을 확인하고 재점검하세요.")])
    return enriched


def _dynamic_pii_leak_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = str(finding.get("evidence", ""))
    if "Strong identifier tier" in evidence:
        return {
            "ko_title": "공개 응답에 강한 개인정보 식별자 후보가 있습니다",
            "easy": "로그인 없이 받은 응답에서 주민번호/외국인번호/여권/면허/CI/DI/계좌/카드 같은 강한 식별자 후보가 감지됐습니다. 회사 안내 연락처보다 훨씬 높은 우선순위로 확인해야 합니다. 원문 값은 표시하지 않았습니다.",
            "fix_steps": [
                "근거의 종류와 개수를 먼저 봅니다. RRN/FRN/여권/면허/CI/DI/카드가 실제 값이면 공개 응답에서 즉시 제거해야 합니다.",
                "계좌번호만 단독으로 나온 경우 공개 입금 계좌인지, 사용자/정산/환불 계좌인지 구분합니다.",
                "사용자/고객/환자/회원 데이터라면 로그인 뒤에서만 내려보내고, 필요 없는 필드는 응답에서 제거하거나 마스킹합니다.",
                "정규식 오탐이라면 false-positive fixture에 추가해 같은 패턴이 다시 high로 뜨지 않게 튜닝합니다.",
            ],
        }
    if "Bulk record tier" in evidence:
        return {
            "ko_title": "응답에 개인정보 목록 묶음이 있습니다",
            "easy": "이름/메일/전화/주소 같은 항목이 여러 건 반복되어 사용자 목록이나 고객 데이터셋처럼 보입니다. 원문 값은 표시하지 않았습니다.",
            "fix_steps": [
                "공개 회사 연락처 목록인지, 실제 사용자/고객 목록인지 확인합니다.",
                "사용자/고객 목록이면 인증을 걸고 페이지네이션, 필드 최소화, 마스킹을 적용합니다.",
                "공개 안내 목록이라면 프로젝트 allowlist나 FP fixture로 분리합니다.",
            ],
        }
    if "Linked record tier" in evidence:
        return {
            "ko_title": "응답에 연결된 개인정보 레코드가 있습니다",
            "easy": "이름과 연락처, 주문번호와 연락처처럼 서로 결합되면 개인을 식별할 수 있는 레코드가 감지됐습니다. 원문 값은 표시하지 않았습니다.",
            "fix_steps": [
                "해당 레코드가 테스트/샘플인지 실제 사용자 데이터인지 확인합니다.",
                "실제 사용자 데이터라면 공개 응답에서 제거하고 인증된 API로 분리합니다.",
                "필요한 항목만 내려보내고 식별자는 마스킹합니다.",
            ],
        }
    return RULE_GUIDANCE["DYN_RESPONSE_PII_LEAK"]


def _exposure_map(rule_ids: list[str], *, review_complete: bool = True) -> list[dict[str, Any]]:
    groups = [
        ("homepage", "홈페이지", "/", ["DYN_SECURITY_HEADERS_MISSING", "DYN_DEBUG_ERROR_LEAK", "DYN_DIRECTORY_LISTING"]),
        ("admin", "관리자", "/admin", ["DYN_UNAUTH_ADMIN_ACCESS", "DYN_ADMIN_ROUTE_REVIEW_REQUIRED"]),
        ("api", "API", "/api, /api/users", ["DYN_UNAUTH_API_JSON", "DYN_RESPONSE_PII_LEAK", "DYN_RESPONSE_PII_REVIEW", "DYN_RESPONSE_SECRET_LEAK"]),
        ("docs", "API 문서", "/swagger.json, /openapi.json", ["DYN_OPENAPI_EXPOSED"]),
        ("sourcemap", "소스맵", "/_next/.../*.map", ["DYN_SOURCE_MAP_ACCESSIBLE"]),
        ("cors", "CORS", "OPTIONS /", ["DYN_CORS_WILDCARD", "DYN_CORS_WILDCARD_CREDENTIALS"]),
        ("deep", "심화 노출", ".env/.git/backup/debug", ["DYN_EXPOSED_ENV_FILE", "DYN_EXPOSED_GIT_CONFIG", "DYN_EXPOSED_BACKUP_OR_DUMP", "DYN_PUBLIC_DEBUG_ENDPOINT"]),
    ]
    present = set(rule_ids)
    return [
        {
            "id": group_id,
            "label": label,
            "path": path,
            "rule_ids": [rule_id for rule_id in group_rules if rule_id in present],
            "status": "unknown" if not review_complete else ("finding" if any(rule_id in present for rule_id in group_rules) else "clear"),
        }
        for group_id, label, path, group_rules in groups
    ]


def _legacy_dashboard_html() -> str:
    checks = json.dumps(CHECKS, ensure_ascii=False)
    non_goals = json.dumps(NON_GOALS, ensure_ascii=False)
    active_paths = json.dumps(DEFAULT_PATHS, ensure_ascii=False)
    active_deep_paths = json.dumps(DEFAULT_ACTIVE_DEEP_PATHS, ensure_ascii=False)
    verification = json.dumps(_verification_info(), ensure_ascii=False)
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>안경선배 | K-Guard MCP</title>
  <style>
    :root {{
      --bg: #eef0e9;
      --ink: #171a18;
      --muted: #606960;
      --line: #cbd1c7;
      --panel: #fafbf7;
      --accent: #176645;
      --terminal: #111613;
      --neon: #9cff57;
      --magenta: #d957a8;
      --flannel: #c94352;
      --danger: #b42318;
      --warn: #b54708;
      --high: #9a3412;
      --ok: #067647;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }}
    main {{ max-width: 1240px; margin: 0 auto; padding: 24px; }}
    header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }}
    nav {{ display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }}
    .brandline {{ margin-bottom: 5px; color: var(--accent); font: 750 12px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    nav a {{ color: #f7f8f2; border: 1px solid #36413a; background: var(--terminal); border-radius: 6px; padding: 8px 10px; font-size: 13px; font-weight: 750; text-decoration: none; }}
    h1 {{ font-size: 28px; line-height: 1.15; margin: 0 0 6px; letter-spacing: 0; }}
    h2 {{ font-size: 16px; margin: 0 0 12px; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.55; }}
    .panel.scope-brief {{ margin-bottom: 16px; color: #f7f8f2; background: var(--terminal); border-color: #303831; border-left: 6px solid var(--flannel); }}
    .scope-brief h2 {{ color: var(--neon); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .scope-brief p {{ color: #cbd3ca; }}
    .scope-steps {{ display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap: 8px; margin-top: 12px; }}
    .scope-step {{ border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 10px; min-height: 92px; }}
    .scope-step strong {{ display: block; font-size: 13px; margin-bottom: 5px; }}
    .scope-step span {{ display: block; color: var(--muted); font-size: 12px; line-height: 1.4; }}
    .grid {{ display: grid; grid-template-columns: minmax(340px, 420px) 1fr; gap: 16px; align-items: start; }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
    .scan-box {{ display: grid; gap: 12px; }}
    label {{ font-size: 13px; font-weight: 650; color: #303630; }}
    input[type="url"] {{ width: 100%; height: 42px; border: 1px solid #aeb7ac; border-radius: 6px; padding: 0 12px; font-size: 15px; background: white; }}
    input[type="url"]:focus {{ outline: 3px solid #b7ef9c; border-color: var(--accent); }}
    .checkline {{ display: grid; grid-template-columns: 18px 1fr; gap: 8px; align-items: start; color: #303630; font-size: 13px; line-height: 1.45; }}
    .checkline input {{ margin-top: 2px; }}
    button {{ height: 42px; border: 1px solid #36413a; border-radius: 6px; background: var(--terminal); color: var(--neon); font-weight: 800; cursor: pointer; }}
    button:hover {{ border-color: var(--magenta); }}
    button:disabled {{ opacity: .55; cursor: wait; }}
    .paths {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
    .pill {{ border: 1px solid var(--line); background: #f4f6f1; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #303630; }}
    .code {{ font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 12px; color: #344054; overflow-wrap: anywhere; background: #f8fafc; border: 1px solid var(--line); border-radius: 6px; padding: 8px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(5, minmax(88px, 1fr)); gap: 8px; margin-bottom: 14px; }}
    .metric {{ border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fbfcff; }}
    .metric strong {{ display: block; font-size: 22px; line-height: 1; margin-bottom: 4px; }}
    .metric span {{ color: var(--muted); font-size: 12px; }}
    .critical strong {{ color: var(--danger); }}
    .high strong {{ color: var(--high); }}
    .medium strong {{ color: var(--warn); }}
    .low strong {{ color: #475467; }}
    .info strong {{ color: var(--accent); }}
    .finding {{ border: 1px solid var(--line); border-left: 4px solid #98a2b3; border-radius: 8px; padding: 12px; margin-bottom: 10px; background: white; }}
    .finding.critical {{ border-left-color: var(--danger); }}
    .finding.high {{ border-left-color: var(--high); }}
    .finding.medium {{ border-left-color: var(--warn); }}
    .finding.info {{ border-left-color: var(--accent); }}
    .finding h3 {{ margin: 0 0 6px; font-size: 14px; }}
    .finding dl {{ display: grid; grid-template-columns: 92px 1fr; gap: 5px 10px; margin: 8px 0 0; font-size: 13px; }}
    .finding dt {{ color: var(--muted); }}
    .finding dd {{ margin: 0; overflow-wrap: anywhere; }}
    .flow-wrap {{ margin: 12px 0 14px; border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 10px; }}
    .flow-wrap svg {{ width: 100%; height: auto; display: block; }}
    .audit-wrap {{ margin: 12px 0 14px; border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 12px; }}
    .audit-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 10px; margin-bottom: 8px; }}
    .audit-head strong {{ font-size: 14px; }}
    .audit-head span {{ font-size: 12px; color: var(--muted); }}
    .audit-list {{ display: grid; gap: 8px; max-height: 420px; overflow: auto; padding-right: 4px; }}
    .audit-row {{ border: 1px solid var(--line); border-left: 4px solid #98a2b3; border-radius: 8px; background: white; padding: 9px; }}
    .audit-row.finding {{ border-left-color: var(--warn); }}
    .audit-row.review {{ border-left-color: var(--accent); }}
    .audit-row.error {{ border-left-color: var(--danger); }}
    .audit-title {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 13px; font-weight: 750; }}
    .audit-meta {{ color: var(--muted); font-size: 12px; overflow-wrap: anywhere; margin-top: 4px; }}
    .audit-outcome {{ color: #344054; font-size: 12px; line-height: 1.45; margin-top: 5px; }}
    .badge {{ border-radius: 5px; padding: 2px 7px; font-size: 11px; border: 1px solid var(--line); background: #f8fafc; color: #344054; }}
    .badge.pass {{ color: var(--ok); border-color: #abefc6; background: #ecfdf3; }}
    .badge.finding {{ color: var(--warn); border-color: #fedf89; background: #fffaeb; }}
    .badge.review {{ color: var(--accent); border-color: #b9e6fe; background: #eff8ff; }}
    .badge.error {{ color: var(--danger); border-color: #fecdca; background: #fef3f2; }}
    .steps {{ margin: 8px 0 0; padding-left: 18px; color: #344054; font-size: 13px; line-height: 1.5; }}
    .checks {{ display: grid; gap: 8px; }}
    .checks-panel {{ margin-top: 16px; overflow: visible; }}
    .checks-panel .checks {{ grid-template-columns: repeat(2, minmax(0, 1fr)); align-items: stretch; }}
    .check-card {{ min-width: 0; border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fbfcff; overflow-wrap: anywhere; }}
    .check-card strong {{ display: block; font-size: 13px; margin-bottom: 4px; }}
    .check-card span {{ display: block; color: var(--muted); font-size: 12px; line-height: 1.45; }}
    .empty {{ color: var(--ok); border: 1px solid #abefc6; background: #ecfdf3; padding: 12px; border-radius: 8px; }}
    .error {{ color: var(--danger); border: 1px solid #fecdca; background: #fef3f2; padding: 12px; border-radius: 8px; }}
    details {{ border-top: 1px solid var(--line); padding-top: 10px; }}
    summary {{ color: var(--accent); cursor: pointer; font-size: 13px; font-weight: 750; }}
    details > div {{ margin-top: 12px; }}
    @media (max-width: 860px) {{
      main {{ padding: 16px; }}
      header, .grid {{ display: block; }}
      nav {{ justify-content: flex-start; margin-top: 12px; }}
      .panel {{ margin-bottom: 14px; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .scope-steps {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .checks-panel .checks {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <div class="brandline">K-GUARD MCP / VIBE CODING SENPAI</div>
      <h1>안경선배</h1>
      <p>내가 만든 앱, 출하 전에 선배한테 한 번 보여주고 갑니다.</p>
    </div>
    <nav>
      <a href="/scope">검수 범위</a>
    </nav>
  </header>
  <section class="panel scope-brief">
    <h2>만드는 흐름은 끊지 않고, 출하는 대충 넘기지 않습니다.</h2>
    <p>이 화면은 권한 있는 사이트의 동적 응답을 확인합니다. 최종 출하 판정은 MCP의 Guardian high 게이트에서 받습니다.</p>
  </section>
  <div class="grid">
    <section class="panel scan-box">
      <div>
        <label for="url">검수할 사이트</label>
        <input id="url" type="url" placeholder="https://example.com" autocomplete="off">
      </div>
      <label class="checkline">
        <input id="authorized" type="checkbox">
        <span>나는 이 타깃을 점검할 권한이 있습니다. 외부 도메인은 결과에 권한 근거를 함께 기록합니다.</span>
      </label>
      <label class="checkline">
        <input id="deepActive" type="checkbox">
        <span>권한 있는 심화 점검을 켭니다. 작은 고정 목록의 민감 경로를 GET으로 확인하지만, 로그인/비밀번호 대입/변경 요청/exploit payload는 실행하지 않습니다.</span>
      </label>
      <button id="scan" type="button">선배 검수 시작</button>
      <details>
        <summary>고급 검수 범위</summary>
        <div>
          <h2>권한 근거</h2>
          <div id="verification" class="code"></div>
        </div>
        <div>
          <h2>실행 경로</h2>
          <div id="paths" class="paths"></div>
        </div>
        <div>
          <h2>점검하지 않는 것</h2>
          <div id="nonGoals" class="checks"></div>
        </div>
      </details>
    </section>
    <section id="results" class="panel" aria-live="polite" aria-busy="false">
      <h2>선배 판정</h2>
      <div id="status" class="empty" role="status" aria-live="polite" aria-atomic="true">검수할 사이트를 넣어주세요.</div>
      <div id="metrics" class="metrics" hidden></div>
      <div id="exposureMap" class="flow-wrap" hidden></div>
      <div id="auditLog" class="audit-wrap" hidden></div>
      <div id="findings" aria-live="polite" aria-relevant="additions text"></div>
    </section>
  </div>
  <section class="panel checks-panel">
    <h2>우리가 점검하는 것</h2>
    <div id="checks" class="checks"></div>
  </section>
</main>
<script>
const CHECKS = {checks};
const NON_GOALS = {non_goals};
const ACTIVE_PATHS = {active_paths};
const ACTIVE_DEEP_PATHS = {active_deep_paths};
const VERIFY = {verification};
const scanButton = document.getElementById('scan');
const urlInput = document.getElementById('url');
const authInput = document.getElementById('authorized');
const deepInput = document.getElementById('deepActive');
const resultsBox = document.getElementById('results');
const statusBox = document.getElementById('status');
const metricsBox = document.getElementById('metrics');
const findingsBox = document.getElementById('findings');
const auditBox = document.getElementById('auditLog');

function text(tag, value, className) {{
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}}

function renderStatic() {{
  const checks = document.getElementById('checks');
  CHECKS.forEach(item => {{
    const card = document.createElement('div');
    card.className = 'check-card';
    card.appendChild(text('strong', item.name));
    card.appendChild(text('span', item.description));
    card.appendChild(text('span', item.rule_ids.join(', ')));
    checks.appendChild(card);
  }});
  const paths = document.getElementById('paths');
  ACTIVE_PATHS.forEach(path => paths.appendChild(text('span', path, 'pill')));
  ACTIVE_DEEP_PATHS.forEach(path => paths.appendChild(text('span', '심화 ' + path, 'pill')));
  const nonGoals = document.getElementById('nonGoals');
  NON_GOALS.forEach(item => nonGoals.appendChild(text('div', item, 'check-card')));
  document.getElementById('verification').textContent =
    VERIFY.allowlist_env + '=example.com,api.example.com\\n' +
    VERIFY.domain_proof_path + ' -> ' + VERIFY.domain_proof_value;
}}

function renderMetrics(summary) {{
  metricsBox.hidden = false;
  metricsBox.replaceChildren();
  ['critical', 'high', 'medium', 'low', 'info'].forEach(key => {{
    const item = document.createElement('div');
    item.className = 'metric ' + key;
    item.appendChild(text('strong', String(summary[key] || 0)));
    item.appendChild(text('span', key));
    metricsBox.appendChild(item);
  }});
}}

function renderFindings(findings) {{
  findingsBox.replaceChildren();
  if (!findings.length) {{
    findingsBox.appendChild(text('div', '현재 점검 범위에서 발견된 항목이 없습니다.', 'empty'));
    return;
  }}
  findings.forEach(finding => {{
    const card = document.createElement('article');
    card.className = 'finding ' + finding.severity;
    card.appendChild(text('h3', (finding.ko_title || finding.title) + ' · ' + finding.rule_id));
    card.appendChild(text('p', finding.easy_explanation || '확인이 필요한 항목입니다.'));
    const dl = document.createElement('dl');
    const rows = [
      ['위험도', finding.severity],
      ['확신도', finding.confidence || ''],
      ['url', finding.url || ''],
      ['요청', finding.method || ''],
      ['상태', finding.status == null ? '' : String(finding.status)],
      ['근거', finding.evidence || ''],
      ['개인정보 분류', finding.privacy_class || ''],
      ['검사 깊이', finding.audit_depth ? 'Depth ' + finding.audit_depth : ''],
      ['개보위 참고', finding.pipc_basis || ''],
      ['검사 범위', finding.inspected_scope || ''],
      ['미검사 범위', finding.not_inspected || '']
    ];
    rows.forEach(([key, value]) => {{
      if (!value) return;
      dl.appendChild(text('dt', key));
      dl.appendChild(text('dd', value));
    }});
    card.appendChild(dl);
    if (finding.fix_steps && finding.fix_steps.length) {{
      const list = document.createElement('ol');
      list.className = 'steps';
      finding.fix_steps.forEach(step => list.appendChild(text('li', step)));
      card.appendChild(list);
    }}
    findingsBox.appendChild(card);
  }});
}}

function renderAuditLog(items) {{
  auditBox.hidden = false;
  auditBox.replaceChildren();
  const head = document.createElement('div');
  head.className = 'audit-head';
  head.appendChild(text('strong', '검사 로그'));
  head.appendChild(text('span', '요청, 확인 기준, 통과/발견 이유 · raw body/value 저장 안 함'));
  auditBox.appendChild(head);
  const list = document.createElement('div');
  list.className = 'audit-list';
  (items || []).forEach(item => {{
    const row = document.createElement('div');
    row.className = 'audit-row ' + (item.result || 'pass');
    const title = document.createElement('div');
    title.className = 'audit-title';
    title.appendChild(text('span', item.result || 'pass', 'badge ' + (item.result || 'pass')));
    title.appendChild(text('span', item.check || '검사'));
    title.appendChild(text('span', (item.method || '') + ' ' + (item.probe_path || ''), 'badge'));
    if (item.status !== null && item.status !== undefined) title.appendChild(text('span', 'HTTP ' + item.status, 'badge'));
    row.appendChild(title);
    row.appendChild(text('div', item.looked_for || '', 'audit-meta'));
    row.appendChild(text('div', item.outcome || '', 'audit-outcome'));
    if (item.rule_ids && item.rule_ids.length) row.appendChild(text('div', item.rule_ids.join(', '), 'audit-meta'));
    row.appendChild(text('div', item.url || '', 'audit-meta'));
    list.appendChild(row);
  }});
  auditBox.appendChild(list);
}}

function renderExposureMap(data) {{
  const box = document.getElementById('exposureMap');
  box.hidden = false;
  const items = data.exposure_map || [];
  const width = 880;
  const height = 250;
  const site = data.target ? data.target.host : 'target';
  const positions = [
    [230, 56], [470, 34], [680, 60],
    [245, 164], [485, 176], [690, 164]
  ];
  const cards = items.map((item, index) => {{
    const [x, y] = positions[index] || [240 + index * 90, 150];
    const count = item.rule_ids.length;
    const fill = count ? '#fef3f2' : '#ecfdf3';
    const stroke = count ? '#f04438' : '#12b76a';
    const title = item.label + (count ? ' · ' + count + '개' : ' · 정상');
    const rules = count ? item.rule_ids.join(', ') : '검출 없음';
    return `
      <line x1="130" y1="120" x2="${{x}}" y2="${{y + 34}}" stroke="#98a2b3" stroke-width="1.5" />
      <rect x="${{x}}" y="${{y}}" width="170" height="76" rx="8" fill="${{fill}}" stroke="${{stroke}}" />
      <text x="${{x + 12}}" y="${{y + 24}}" font-size="14" font-weight="700" fill="#172033">${{escapeSvg(title)}}</text>
      <text x="${{x + 12}}" y="${{y + 44}}" font-size="12" fill="#475467">${{escapeSvg(item.path)}}</text>
      <text x="${{x + 12}}" y="${{y + 63}}" font-size="11" fill="#667085">${{escapeSvg(rules).slice(0, 42)}}</text>
    `;
  }}).join('');
  box.innerHTML = `
    <svg viewBox="0 0 ${{width}} ${{height}}" role="img" aria-label="노출 흐름 지도">
      <rect x="0" y="0" width="${{width}}" height="${{height}}" rx="8" fill="#fbfcff" />
      <text x="18" y="28" font-size="15" font-weight="700" fill="#172033">노출 흐름 지도</text>
      <text x="18" y="48" font-size="12" fill="#667085">대시보드가 고정 경로에 GET/OPTIONS 요청을 보내고, 응답에서 위험 신호를 찾습니다.</text>
      <rect x="24" y="88" width="120" height="64" rx="8" fill="#eff8ff" stroke="#2e90fa" />
      <text x="42" y="114" font-size="14" font-weight="700" fill="#172033">K-Guard</text>
      <text x="42" y="135" font-size="12" fill="#475467">GET/OPTIONS</text>
      <rect x="24" y="176" width="120" height="42" rx="8" fill="#ffffff" stroke="#d7dde8" />
      <text x="39" y="202" font-size="12" fill="#475467">${{escapeSvg(site)}}</text>
      ${{cards}}
    </svg>`;
}}

function escapeSvg(value) {{
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#x27;');
}}

async function scan() {{
  scanButton.disabled = true;
  resultsBox.setAttribute('aria-busy', 'true');
  statusBox.className = 'empty';
  statusBox.textContent = deepInput.checked
    ? '점검 중입니다. 기본 경로와 심화 민감 경로에 대해 GET/OPTIONS 요청만 실행합니다.'
    : '점검 중입니다. 고정 경로에 대해 GET/OPTIONS 요청만 실행합니다.';
  metricsBox.hidden = true;
  auditBox.hidden = true;
  findingsBox.replaceChildren();
  auditBox.replaceChildren();
  try {{
    const response = await fetch('/api/scan', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json', 'X-K-Guard-CSRF': '__K_GUARD_CSRF__'}},
      body: JSON.stringify({{url: urlInput.value, authorized: authInput.checked, deep_active: deepInput.checked}})
    }});
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error('scan failed');
    const blockingCount = Number(data.summary.critical || 0) + Number(data.summary.high || 0);
    const auth = data.target.authorization || {{method: 'unknown'}};
    statusBox.className = blockingCount ? 'error' : 'empty';
    statusBox.textContent = blockingCount
      ? '고치고 다시 봅시다. 출하 전에 확인할 high 이상 항목이 ' + blockingCount + '개 있습니다. 권한 근거: ' + auth.method
      : '현재 동적 범위에서 큰 위험 신호는 없습니다. 최종 출하 판정은 Guardian high 게이트로 확인하세요. 권한 근거: ' + auth.method;
    renderMetrics(data.summary);
    renderExposureMap(data);
    renderAuditLog(data.audit_log);
    renderFindings(data.findings);
  }} catch (error) {{
    statusBox.className = 'error';
    statusBox.textContent = '검수를 완료하지 못했습니다. 입력 주소와 실행 상태를 확인한 뒤 다시 시도하세요.';
  }} finally {{
    scanButton.disabled = false;
    resultsBox.setAttribute('aria-busy', 'false');
  }}
}}

scanButton.addEventListener('click', scan);
urlInput.addEventListener('keydown', event => {{ if (event.key === 'Enter') scan(); }});
renderStatic();
</script>
</body>
</html>"""


def _legacy_scope_html() -> str:
    return """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>안경선배 검수 범위 | K-Guard MCP</title>
  <style>
    :root {
      --bg: #eef0e9;
      --ink: #171a18;
      --muted: #606960;
      --line: #cbd1c7;
      --panel: #fafbf7;
      --accent: #176645;
      --green: #067647;
      --amber: #b54708;
      --red: #b42318;
      --blue: #175cd3;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: flex-start; gap: 18px; margin-bottom: 16px; }
    h1 { font-size: 30px; line-height: 1.15; margin: 0 0 8px; letter-spacing: 0; }
    h2 { font-size: 18px; margin: 0 0 12px; }
    h3 { font-size: 14px; margin: 0 0 8px; }
    p { margin: 0; color: var(--muted); line-height: 1.55; }
    a { color: var(--accent); font-weight: 750; text-decoration: none; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .hero { display: grid; grid-template-columns: minmax(280px, 1fr) minmax(320px, 460px); gap: 16px; align-items: stretch; }
    .verdict { border-left: 5px solid var(--amber); background: #fffaeb; }
    .verdict strong { color: #7a2e0e; }
    .pipeline { display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap: 8px; margin-top: 12px; }
    .step { border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 10px; min-height: 112px; position: relative; }
    .step::after { content: ""; position: absolute; right: -8px; top: 50%; width: 8px; border-top: 2px solid #98a2b3; }
    .step:last-child::after { display: none; }
    .step b { display: inline-flex; width: 24px; height: 24px; align-items: center; justify-content: center; border-radius: 999px; background: #eff8ff; color: var(--blue); font-size: 12px; margin-bottom: 8px; }
    .step strong { display: block; font-size: 13px; margin-bottom: 5px; }
    .step span { display: block; color: var(--muted); font-size: 12px; line-height: 1.42; }
    .depth-grid { display: grid; grid-template-columns: repeat(3, minmax(220px, 1fr)); gap: 10px; }
    .depth-card { border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 12px; }
    .depth-card strong { display: flex; justify-content: space-between; gap: 8px; font-size: 14px; margin-bottom: 8px; }
    .depth-card p { font-size: 13px; }
    .chip { display: inline-flex; align-items: center; justify-content: center; min-width: 48px; border-radius: 999px; padding: 2px 8px; font-size: 12px; border: 1px solid var(--line); background: #fff; color: #344054; }
    .l4, .l5 { color: var(--green); border-color: #abefc6; background: #ecfdf3; }
    .l3 { color: var(--blue); border-color: #b9e6fe; background: #eff8ff; }
    .l2 { color: var(--amber); border-color: #fedf89; background: #fffaeb; }
    .l0 { color: var(--red); border-color: #fecdca; background: #fef3f2; }
    .matrix { width: 100%; border-collapse: collapse; background: white; }
    .matrix th, .matrix td { border: 1px solid var(--line); padding: 9px; text-align: left; vertical-align: top; font-size: 13px; }
    .matrix th { background: #eef2f7; color: #344054; }
    .map { width: 100%; overflow: hidden; border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; }
    .map svg { width: 100%; height: auto; display: block; }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .list { display: grid; gap: 8px; }
    .item { border: 1px solid var(--line); border-radius: 8px; background: #fbfcff; padding: 10px; }
    .item strong { display: block; font-size: 13px; margin-bottom: 4px; }
    .item span { display: block; color: var(--muted); font-size: 12px; line-height: 1.45; }
    .bad { border-left: 4px solid var(--red); }
    .ok { border-left: 4px solid var(--green); }
    .todo { border-left: 4px solid var(--amber); }
    @media (max-width: 900px) {
      main { padding: 16px; }
      header, .hero, .split { display: block; }
      .pipeline { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .step::after { display: none; }
      .depth-grid { grid-template-columns: 1fr; }
      .matrix { display: block; width: 100%; max-width: 100%; overflow-x: auto; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>안경선배가 어디까지 보는지</h1>
      <p>K-Guard MCP의 자동 검수 범위와 아직 사람이 확인해야 하는 경계를 한 화면에 정리합니다.</p>
    </div>
    <a href="/">대시보드로 돌아가기</a>
  </header>

  <section class="panel verdict">
    <h2>현재 제품 판정</h2>
    <p><strong>시니어 개발자의 출하 전 검수 질문을 자동화한 fail-closed 게이트입니다.</strong> 사이트, API, 데이터, 운영 네 영역을 묶어 보지만 인간의 사업 판단, 법률 판단, 완전한 타입·프레임워크 이해, 원격 운영 DB와 실제 파기 실행을 대신하지는 않습니다.</p>
  </section>

  <section class="panel hero">
    <div>
      <h2>감사 파이프라인</h2>
      <p>사용자가 권한 있는 대상을 넣으면, K-Guard는 read-only evidence를 모아 위험 신호를 판단합니다. 기본 모드는 안전 점검, 심화 모드는 작은 고정 목록의 대표 개구멍까지 확인합니다.</p>
      <div class="pipeline">
        <div class="step"><b>1</b><strong>권한 확인</strong><span>local target, allowlist, domain proof, 사용자 attestation 기록</span></div>
        <div class="step"><b>2</b><strong>정적/AST 스캔</strong><span>코드, env, API key, 한국형 개인정보, Python AST taint 검사</span></div>
        <div class="step"><b>3</b><strong>설정 스캔</strong><span>CORS, source map, OpenAPI, 보안 헤더, debug marker 확인</span></div>
        <div class="step"><b>4</b><strong>동적/세션 검증</strong><span>고정 경로 GET/OPTIONS, 심화 민감 경로, 사용자 제공 세션 read-only probe</span></div>
        <div class="step"><b>5</b><strong>런타임/저장소</strong><span>MCP JSONL event, SQLite, log, storage를 read-only로 관찰</span></div>
        <div class="step"><b>6</b><strong>판정/보고서</strong><span>cross-plane verdict, FP/FN scoreboard, SARIF/CI 결과 생성</span></div>
      </div>
    </div>
    <div class="map">
      <svg viewBox="0 0 520 420" role="img" aria-label="K-Guard raw-free evidence graph">
        <rect x="0" y="0" width="520" height="420" rx="8" fill="#fbfcff"/>
        <text x="24" y="34" font-size="17" font-weight="700" fill="#172033">Raw-free Evidence Graph</text>
        <text x="24" y="56" font-size="12" fill="#667085">원문 값은 저장하지 않고 class/hash/route/sink만 연결</text>
        <rect x="28" y="96" width="132" height="58" rx="8" fill="#eff8ff" stroke="#2e90fa"/>
        <text x="48" y="121" font-size="13" font-weight="700" fill="#172033">수집 지점</text>
        <text x="48" y="141" font-size="11" fill="#475467">form, API, file</text>
        <rect x="194" y="96" width="132" height="58" rx="8" fill="#ecfdf3" stroke="#12b76a"/>
        <text x="214" y="121" font-size="13" font-weight="700" fill="#172033">분류/마스킹</text>
        <text x="214" y="141" font-size="11" fill="#475467">KR PII, secret</text>
        <rect x="360" y="96" width="132" height="58" rx="8" fill="#fffaeb" stroke="#f79009"/>
        <text x="380" y="121" font-size="13" font-weight="700" fill="#172033">증거 저장</text>
        <text x="380" y="141" font-size="11" fill="#475467">HMAC hash</text>
        <line x1="160" y1="125" x2="194" y2="125" stroke="#98a2b3" stroke-width="2"/>
        <line x1="326" y1="125" x2="360" y2="125" stroke="#98a2b3" stroke-width="2"/>
        <rect x="28" y="226" width="132" height="58" rx="8" fill="#fff" stroke="#d7dde8"/>
        <text x="48" y="250" font-size="13" font-weight="700" fill="#172033">응답</text>
        <text x="48" y="270" font-size="11" fill="#475467">HTML/JSON/API</text>
        <rect x="194" y="226" width="132" height="58" rx="8" fill="#fff" stroke="#d7dde8"/>
        <text x="214" y="250" font-size="13" font-weight="700" fill="#172033">로그/외부전송</text>
        <text x="214" y="270" font-size="11" fill="#475467">log, HTTP sink</text>
        <rect x="360" y="226" width="132" height="58" rx="8" fill="#fff" stroke="#d7dde8"/>
        <text x="380" y="250" font-size="13" font-weight="700" fill="#172033">LLM/MCP</text>
        <text x="380" y="270" font-size="11" fill="#475467">tool call boundary</text>
        <line x1="260" y1="154" x2="94" y2="226" stroke="#98a2b3" stroke-width="2"/>
        <line x1="260" y1="154" x2="260" y2="226" stroke="#98a2b3" stroke-width="2"/>
        <line x1="260" y1="154" x2="426" y2="226" stroke="#98a2b3" stroke-width="2"/>
        <rect x="78" y="340" width="364" height="44" rx="8" fill="#eff8ff" stroke="#b9e6fe"/>
        <text x="108" y="367" font-size="13" font-weight="700" fill="#172033">Dashboard · Markdown · JSON · SARIF · CI fail-on</text>
      </svg>
    </div>
  </section>

  <section class="panel">
    <h2>감사 깊이 지도</h2>
    <div class="depth-grid">
      <div class="depth-card"><strong>Python AST taint <span class="chip l5">L4-L5</span></strong><p>request/DB/env source가 log, response, DB write, external HTTP, LLM/MCP call로 가는지 AST로 연결합니다.</p></div>
      <div class="depth-card"><strong>동적/세션 웹 검증 <span class="chip l4">L4</span></strong><p>허용된 origin에서 고정 경로와 심화 민감 경로를 직접 열고, 사용자 제공 세션 헤더는 GET 요청에만 붙여 read-only로 확인합니다.</p></div>
      <div class="depth-card"><strong>SARIF/CI/evidence hash <span class="chip l5">L4-L5</span></strong><p>결과를 CI에서 막을 수 있고, finding fingerprint와 HMAC evidence hash를 남깁니다.</p></div>
      <div class="depth-card"><strong>한국형 개인정보 <span class="chip l3">L2-L3</span></strong><p>주민번호, 외국인번호, 여권, 운전면허, CI/DI, 건강/계좌/카드, 결합 개인정보를 봅니다.</p></div>
      <div class="depth-card"><strong>MCP runtime observer <span class="chip l4">L4-L5</span></strong><p>JSONL 또는 이벤트 단위 tool_result/tool_call에서 PII, hidden instruction, agentic/external sink 이동과 block/redact policy 결정을 관찰합니다.</p></div>
      <div class="depth-card"><strong>MCP/LLM 정적 위협 <span class="chip l2">L2-L3</span></strong><p>tool poisoning, hidden instruction, exfiltration intent, 위험 명령 패턴을 rule 기반으로 탐지합니다.</p></div>
      <div class="depth-card"><strong>데이터 흐름 그래프 <span class="chip l3">L3-L5</span></strong><p>Python은 AST taint, JS/TS는 lightweight taint와 파일/라인/거리 기반 휴리스틱으로 source와 sink를 연결합니다.</p></div>
      <div class="depth-card"><strong>DB/log/storage connector <span class="chip l4">L4</span></strong><p>로컬 SQLite, log, JSON/CSV/TSV storage를 read-only로 열고 count-only PII/secret evidence를 남깁니다.</p></div>
      <div class="depth-card"><strong>보존/삭제 검증 <span class="chip l3">L3</span></strong><p>개인정보 신호가 있는데 retention/deletion marker가 없는지 확인합니다. 실제 삭제 실행은 아직 별도입니다.</p></div>
      <div class="depth-card"><strong>FP/FN scoreboard <span class="chip l4">L4</span></strong><p>한국형 fixture corpus 기준 recall과 false positive rate를 CLI/MCP에서 정량 산출합니다.</p></div>
      <div class="depth-card"><strong>원격 DB/백업/실제 삭제 <span class="chip l0">L0-L1</span></strong><p>운영 DB, 백업 저장소와 실제 삭제 실행 검증은 다음 내핵 단계로 남아 있습니다.</p></div>
    </div>
  </section>

  <section class="panel">
    <h2>무엇을 어떻게 보는가</h2>
    <table class="matrix">
      <thead><tr><th>영역</th><th>검사 방법</th><th>찾는 신호</th><th>현재 한계</th></tr></thead>
      <tbody>
        <tr><td>코드/텍스트</td><td>로컬 정적 스캔 + Python AST taint + JS/TS lightweight taint + limited route-to-service summary</td><td>한국형 PII, secret, env, API key, request source-to-sink</td><td>JS/TS 정밀 AST, 타입 해석, 완전한 inter-procedural taint는 다음 단계</td></tr>
        <tr><td>설정/빌드 산출물</td><td>파일/패턴 검사와 동적 확인</td><td>source map, OpenAPI, CORS, security header, debug marker</td><td>framework별 자동 수정은 아직 제한적</td></tr>
        <tr><td>웹 런타임</td><td>GET/OPTIONS only probe + bounded deep exposure paths + session-file headers</td><td>무인증 API JSON, 관리자 기능 단서, 공개 문서, 공개 source map, .env/.git/backup/debug 노출, 세션 내부 read-only 응답</td><td>폼 제출, mutation, brute force, exploit chain은 하지 않음</td></tr>
        <tr><td>개인정보 흐름</td><td>휴리스틱 flow graph + AST + cross-plane verdict</td><td>입력/응답/로그/외부 HTTP/LLM/MCP sink 후보와 결합 판정</td><td>정확한 record lineage와 모든 전송계층 상관관계는 아직 제한적</td></tr>
        <tr><td>MCP/LLM</td><td>manifest/prompt rule + JSONL observer + stdio live proxy</td><td>hidden instruction, exfiltration, dangerous command, tool result PII, 전달 전 block/redact</td><td>현재 live 집행은 line-delimited stdio JSON-RPC에 한정</td></tr>
        <tr><td>저장소/보존</td><td>SQLite/log/storage read-only connector + marker scan</td><td>PII at rest, secret at rest, retention/deletion marker gap</td><td>원격 DB, 백업, 실제 삭제 실행은 아직 확인하지 않음</td></tr>
        <tr><td>보고/운영</td><td>JSON, Markdown, SARIF, dashboard, score-corpus</td><td>raw-free evidence, confidence, audit depth, PIPC-style 설명, recall/FPR</td><td>법적 인증이나 보증은 아님</td></tr>
      </tbody>
    </table>
  </section>

  <section class="panel split">
    <div>
      <h2>현재 하는 것</h2>
      <div class="list">
        <div class="item ok"><strong>원문 미저장</strong><span>개인정보 값 대신 masked value와 evidence hash를 남깁니다.</span></div>
        <div class="item ok"><strong>권한 경계 기록</strong><span>외부 도메인은 사용자 attestation, allowlist, domain proof를 결과에 기록합니다.</span></div>
        <div class="item ok"><strong>비파괴 동적 점검</strong><span>로그인 시도, form submit, mutation, fuzzing 없이 GET/OPTIONS만 실행하며 세션 헤더도 read-only로만 사용합니다.</span></div>
        <div class="item ok"><strong>권한 있는 심화 점검</strong><span>사용자가 켜면 .env, .git/config, backup.sql, phpinfo, server-status, actuator/env 같은 작은 고정 목록을 확인합니다. 이것은 무차별 경로 탐색이 아니라 대표 사고 패턴 검증입니다.</span></div>
        <div class="item ok"><strong>내핵 후보 검사</strong><span>AST taint, runtime MCP observer, SQLite/log/storage connector, cross-plane verdict, score-corpus를 실행합니다.</span></div>
        <div class="item ok"><strong>한국어 해설</strong><span>바이브코더가 이해할 수 있게 의미, 오탐 가능성, 수정 방법을 같이 보여줍니다.</span></div>
      </div>
    </div>
    <div>
      <h2>아직 하지 않는 것</h2>
      <div class="list">
        <div class="item bad"><strong>공격적 침투</strong><span>비밀번호 대입, 대량 경로 사전, mutation, destructive request, exploit chain은 하지 않습니다. exploit payload와 권한 우회 검증은 별도 staging/전문 도구 연계 모드로 분리해야 합니다.</span></div>
        <div class="item todo"><strong>원격 저장소/백업</strong><span>Postgres/Supabase/Firebase/S3/백업 저장소 connector는 다음 단계입니다.</span></div>
        <div class="item todo"><strong>추가 MCP 전송계층</strong><span>stdio JSONL과 Streamable HTTP POST·GET SSE·DELETE는 프록시합니다. binary framing과 비표준 transport의 범용 proxy는 아직 지원하지 않습니다.</span></div>
        <div class="item todo"><strong>실제 삭제 실행 검증</strong><span>삭제 API를 실행하거나 백업 purging을 증명하는 단계는 아직 하지 않습니다.</span></div>
      </div>
    </div>
  </section>
</main>
</body>
</html>"""


def _dashboard_html() -> str:
    return render_dashboard(CHECKS, NON_GOALS, DEFAULT_PATHS, DEFAULT_ACTIVE_DEEP_PATHS, _verification_info())


def _scope_html() -> str:
    return render_scope()


if __name__ == "__main__":
    raise SystemExit(main())
