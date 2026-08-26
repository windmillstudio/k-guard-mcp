from __future__ import annotations

import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import anyio

from k_guard_mcp import server as mcp_server_module
from k_guard_mcp.reports import to_json
from k_guard_mcp.scanner import KGuardScanner


RAW_MARKERS = [
    "홍길동",
    "010-9876-5432",
    "hong@example-sensitive.co.kr",
    "sk-thisisaverylongfakeapikey000",
    "postgres://alice:supersecret@localhost/app",
    "901225-1234563",
]

EXPECTED_STATIC_RULES = {
    "CONFIG_PUBLIC_ENV_SECRET",
    "FLOW_PII_TO_LOG",
    "KR_COMBO_PERSON_EMAIL",
    "KR_COMBO_PERSON_PHONE",
    "KR_COMBO_VEHICLE_LOCATION_TIME",
    "PII_EMAIL",
    "PII_PHONE",
    "PII_RRN_VALID",
    "SECRET_DB_URL",
    "SECRET_OPENAI_STYLE_KEY",
}

EXPECTED_DYNAMIC_RULES = {
    "DYN_CORS_WILDCARD_CREDENTIALS",
    "DYN_DEBUG_ERROR_LEAK",
    "DYN_OPENAPI_EXPOSED",
    "DYN_RESPONSE_PII_LEAK",
    "DYN_RESPONSE_SECRET_LEAK",
    "DYN_SECURITY_HEADERS_MISSING",
    "DYN_SOURCE_MAP_ACCESSIBLE",
    "DYN_UNAUTH_ADMIN_ACCESS",
    "DYN_UNAUTH_API_JSON",
}


class AuthorizedAuditTarget(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # type: ignore[no-untyped-def]
        return

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._send_text(
                "<html><body><h1>Demo</h1><pre>Traceback (most recent call last): "
                "TypeError: secret config missing</pre></body></html>",
                "text/html; charset=utf-8",
            )
            return
        if self.path == "/admin":
            self._send_text("관리자 대시보드 회원관리 사용자 관리 설정 변경 삭제 승인", "text/html; charset=utf-8")
            return
        if self.path in {"/api", "/api/users"}:
            self._send_text(
                json.dumps(
                    {
                        "name": "홍길동",
                        "phone": "010-9876-5432",
                        "email": "hong@example-sensitive.co.kr",
                        "token": "sk-thisisaverylongfakeapikey000",
                    },
                    ensure_ascii=False,
                ),
                "application/json",
            )
            return
        if self.path in {"/swagger.json", "/openapi.json"}:
            self._send_text(json.dumps({"openapi": "3.0.0", "paths": {"/admin": {}, "/api/users": {}}}), "application/json")
            return
        if self.path == "/_next/static/chunks/app.js.map":
            self._send_text('{"version":3,"sources":["app.ts"],"mappings":""}', "application/json")
            return
        self.send_response(404)
        self.end_headers()

    def _send_text(self, body: str, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = _write_static_target(Path(tmp) / "authorized-audit-target")
        http_server = ThreadingHTTPServer(("127.0.0.1", 0), AuthorizedAuditTarget)
        thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{http_server.server_port}"
            report = _run_harness(root, base_url)
        finally:
            http_server.shutdown()
            thread.join(timeout=5)

    Path("authorized-dynamic-harness-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(_summary(report), ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


def _write_static_target(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / ".env").write_text(
        "DATABASE_URL=postgres://alice:supersecret@localhost/app\n"
        "NEXT_PUBLIC_SECRET_KEY=sk-thisisaverylongfakeapikey000\n",
        encoding="utf-8",
    )
    (root / "route.ts").write_text(
        "export async function POST(req) {\n"
        "  const email = await req.body.email;\n"
        "  console.log(email);\n"
        "  return Response.json({ email });\n"
        "}\n"
        "name=홍길동 phone=010-9876-5432 email=hong@example-sensitive.co.kr rrn=901225-1234563\n",
        encoding="utf-8",
    )
    (root / "users.csv").write_text(
        "name,phone,email,vehicle,location,timestamp\n"
        "홍길동,010-9876-5432,hong@example-sensitive.co.kr,12가 3456,서울시 강남구,2026-07-06 21:05\n",
        encoding="utf-8",
    )
    return root


def _run_harness(root: Path, base_url: str) -> dict[str, object]:
    scanner = KGuardScanner()
    static_result = scanner.scan_workspace(root)
    dynamic_result = scanner.probe_http(base_url)
    mcp_probe_payload = anyio.run(_call_mcp_probe_http, base_url)

    static_payload = to_json(static_result)
    dynamic_payload = to_json(dynamic_result)
    mcp_probe_data = json.loads(mcp_probe_payload)

    static_rules = {finding.rule_id for finding in static_result.findings}
    dynamic_rules = {finding.rule_id for finding in dynamic_result.findings}
    mcp_probe_rules = {finding["rule_id"] for finding in mcp_probe_data.get("findings", [])}
    combined_payload = "\n".join([static_payload, dynamic_payload, mcp_probe_payload])

    static_missing = sorted(EXPECTED_STATIC_RULES - static_rules)
    dynamic_missing = sorted(EXPECTED_DYNAMIC_RULES - dynamic_rules)
    mcp_missing = sorted(EXPECTED_DYNAMIC_RULES - mcp_probe_rules)
    raw_marker_leaks = [marker for marker in RAW_MARKERS if marker in combined_payload]

    return {
        "mode": "authorized_local_dynamic_harness",
        "target": {
            "base_url": "http://127.0.0.1:<ephemeral>",
            "scope": "local 127.0.0.1 test server only",
            "active_paths": ["/", "/admin", "/api", "/api/users", "/swagger.json", "/openapi.json", "/_next/static/chunks/app.js.map"],
        },
        "static": _result_summary(static_result, static_rules, static_missing),
        "dynamic": _result_summary(dynamic_result, dynamic_rules, dynamic_missing),
        "mcp_probe_http": {
            "finding_count": len(mcp_probe_data.get("findings", [])),
            "summary": mcp_probe_data.get("summary", {}),
            "rule_ids": sorted(mcp_probe_rules),
            "missing_expected_rules": mcp_missing,
        },
        "raw_marker_leaks": raw_marker_leaks,
        "passed": not static_missing and not dynamic_missing and not mcp_missing and not raw_marker_leaks,
    }


async def _call_mcp_probe_http(base_url: str) -> str:
    mcp_server = mcp_server_module.create_mcp_server()
    with patch.dict(os.environ, {"K_GUARD_MCP_ENABLE_PROBE": "1"}):
        result = await mcp_server.call_tool("probe_http", {"base_url": base_url})
    return result[0].text


def _result_summary(result, rule_ids: set[str], missing: list[str]) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "finding_count": len(result.findings),
        "summary": json.loads(to_json(result))["summary"],
        "rule_ids": sorted(rule_ids),
        "missing_expected_rules": missing,
    }


def _summary(report: dict[str, object]) -> dict[str, object]:
    return {
        "passed": report["passed"],
        "mode": report["mode"],
        "static_missing": report["static"]["missing_expected_rules"],  # type: ignore[index]
        "dynamic_missing": report["dynamic"]["missing_expected_rules"],  # type: ignore[index]
        "mcp_missing": report["mcp_probe_http"]["missing_expected_rules"],  # type: ignore[index]
        "raw_marker_leaks": report["raw_marker_leaks"],
    }


if __name__ == "__main__":
    raise SystemExit(main())
