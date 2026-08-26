from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from k_guard_mcp.scanner import KGuardScanner


@dataclass(frozen=True)
class Case:
    name: str
    size: str
    path_bodies: dict[str, tuple[str, str]]
    expected_present: set[str]
    expected_absent: set[str]


CASES = [
    Case(
        name="large_general_html_numeric_noise",
        size="large",
        path_bodies={
            "/": (
                "text/html; charset=utf-8",
                "<!doctype html><html><script>"
                "window.__BUILD__='991332-1234567';"
                "window.__ACCOUNT_STATE__='account=123-4567-890123';"
                "window.__PRODUCT__='M12345678';"
                "</script><body>대형 서비스 공개 홈</body></html>",
            )
        },
        expected_present=set(),
        expected_absent={"DYN_RESPONSE_PII_LEAK", "DYN_RESPONSE_PII_REVIEW"},
    ),
    Case(
        name="medium_public_contact_page",
        size="medium",
        path_bodies={
            "/": ("text/html; charset=utf-8", "대표: 홍길동 안내 전화 02-123-4567 이메일 info@example.com 진료 안내")
        },
        expected_present=set(),
        expected_absent={"DYN_RESPONSE_PII_LEAK", "DYN_RESPONSE_PII_REVIEW"},
    ),
    Case(
        name="small_vibecoded_bulk_user_json",
        size="small",
        path_bodies={
            "/api": (
                "application/json",
                json.dumps(
                    [
                        {"name": "홍길동", "email": "user1@example.com"},
                        {"name": "김철수", "email": "user2@example.com"},
                        {"name": "이영희", "email": "user3@example.com"},
                        {"name": "박민수", "email": "user4@example.com"},
                    ],
                    ensure_ascii=False,
                ),
            )
        },
        expected_present={"DYN_RESPONSE_PII_LEAK"},
        expected_absent=set(),
    ),
    Case(
        name="small_valid_strong_identifier_html",
        size="small",
        path_bodies={
            "/": ("text/html; charset=utf-8", "고객 주민등록번호 901225-1234563")
        },
        expected_present={"DYN_RESPONSE_PII_LEAK"},
        expected_absent=set(),
    ),
    Case(
        name="medium_bank_account_json",
        size="medium",
        path_bodies={
            "/api": ("application/json", '{"bank_account":"123-4567-890123"}')
        },
        expected_present={"DYN_RESPONSE_PII_LEAK"},
        expected_absent=set(),
    ),
]


def main() -> int:
    output = Path("site-scale-calibration-report.json")
    report = run_cases()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(output), "passed": report["passed"], "case_count": len(report["cases"])}, ensure_ascii=False))
    return 0 if report["passed"] else 2


def run_cases() -> dict[str, object]:
    cases = [_run_case(case) for case in CASES]
    return {
        "method": "local_blackbox_http_calibration",
        "external_network_used": False,
        "passed": all(case["passed"] for case in cases),
        "cases": cases,
    }


def _run_case(case: Case) -> dict[str, object]:
    handler = _handler_for(case)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = KGuardScanner().probe_http(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        thread.join(timeout=5)
    rule_ids = {finding.rule_id for finding in result.findings}
    missing = sorted(case.expected_present - rule_ids)
    unexpected = sorted(case.expected_absent & rule_ids)
    return {
        "name": case.name,
        "size": case.size,
        "passed": not missing and not unexpected,
        "expected_present": sorted(case.expected_present),
        "expected_absent": sorted(case.expected_absent),
        "missing": missing,
        "unexpected": unexpected,
        "rule_ids": sorted(rule_ids),
        "summary": result.summary(),
    }


def _handler_for(case: Case):
    class CalibrationHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # type: ignore[no-untyped-def]
            return

        def do_GET(self):  # noqa: N802
            if self.path not in case.path_bodies:
                self.send_response(404)
                self.end_headers()
                return
            content_type, body = case.path_bodies[self.path]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def do_OPTIONS(self):  # noqa: N802
            self.send_response(204)
            self.end_headers()

    return CalibrationHandler


if __name__ == "__main__":
    raise SystemExit(main())
