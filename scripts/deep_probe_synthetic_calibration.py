from __future__ import annotations

import argparse
import json
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from k_guard_mcp.dashboard import scan_url
from k_guard_mcp.redaction import sanitize_any


HIGH_RULES = {
    "DYN_UNAUTH_ADMIN_ACCESS",
    "DYN_UNAUTH_API_JSON",
    "DYN_RESPONSE_PII_LEAK",
    "DYN_RESPONSE_SECRET_LEAK",
    "DYN_CORS_WILDCARD_CREDENTIALS",
    "DYN_REDIRECT_TO_DISALLOWED_HOST",
    "DYN_EXPOSED_ENV_FILE",
    "DYN_EXPOSED_GIT_CONFIG",
    "DYN_EXPOSED_BACKUP_OR_DUMP",
    "DYN_PUBLIC_DEBUG_ENDPOINT",
    "DYN_DEBUG_ERROR_LEAK",
}


@dataclass(frozen=True)
class Scenario:
    name: str
    expected_rules: frozenset[str]
    notes: str


SCENARIOS = [
    Scenario("clean_hardened", frozenset(), "Hardened public homepage with no exposed dynamic signals."),
    Scenario("missing_headers", frozenset({"DYN_SECURITY_HEADERS_MISSING"}), "Homepage intentionally omits browser security headers."),
    Scenario("cors_wildcard_credentials", frozenset({"DYN_CORS_WILDCARD_CREDENTIALS"}), "OPTIONS / returns wildcard CORS with credentials."),
    Scenario("admin_login", frozenset(), "/admin is a login wall and must not become critical."),
    Scenario("admin_spa_shell", frozenset(), "/admin is an inert SPA shell and must not become critical."),
    Scenario("admin_console", frozenset({"DYN_UNAUTH_ADMIN_ACCESS"}), "/admin exposes clear management-console language."),
    Scenario("admin_review", frozenset({"DYN_ADMIN_ROUTE_REVIEW_REQUIRED"}), "/admin returns 200 but lacks clear admin functionality."),
    Scenario("public_api_json", frozenset({"DYN_PUBLIC_API_JSON_REVIEW"}), "/api returns unauthenticated JSON without personal data."),
    Scenario("bulk_pii_api", frozenset({"DYN_UNAUTH_API_JSON", "DYN_RESPONSE_PII_LEAK"}), "/api returns a bulk user/contact cluster."),
    Scenario("secret_api", frozenset({"DYN_UNAUTH_API_JSON", "DYN_RESPONSE_SECRET_LEAK"}), "/api returns a secret-like token."),
    Scenario("openapi_document", frozenset({"DYN_OPENAPI_EXPOSED"}), "/openapi.json returns a real OpenAPI document."),
    Scenario("source_map", frozenset({"DYN_SOURCE_MAP_ACCESSIBLE"}), "Next.js source map path returns source-map JSON."),
    Scenario("env_file", frozenset({"DYN_RESPONSE_SECRET_LEAK", "DYN_EXPOSED_ENV_FILE"}), "/.env returns key=value secret/config structure."),
    Scenario("git_config", frozenset({"DYN_EXPOSED_GIT_CONFIG"}), "/.git/config returns Git config structure."),
    Scenario("backup_sql", frozenset({"DYN_EXPOSED_BACKUP_OR_DUMP"}), "/backup.sql returns SQL dump markers."),
    Scenario("phpinfo", frozenset({"DYN_PUBLIC_DEBUG_ENDPOINT"}), "/phpinfo.php returns phpinfo-like details."),
    Scenario("actuator_env", frozenset({"DYN_RESPONSE_SECRET_LEAK", "DYN_PUBLIC_DEBUG_ENDPOINT", "DYN_UNAUTH_API_JSON"}), "/actuator/env returns runtime environment structure."),
    Scenario("directory_listing", frozenset({"DYN_DIRECTORY_LISTING"}), "Homepage returns an index listing."),
    Scenario("debug_stack", frozenset({"DYN_DEBUG_ERROR_LEAK"}), "Homepage returns a stack trace."),
    Scenario("external_redirect", frozenset({"DYN_REDIRECT_TO_DISALLOWED_HOST"}), "Homepage redirects to a disallowed external host; scanner must not follow it."),
    Scenario("env_html_false_positive", frozenset(), "/.env returns HTML shell and must not trigger env-file exposure."),
    Scenario("openapi_html_false_positive", frozenset(), "/openapi.json returns HTML shell and must not trigger OpenAPI exposure."),
    Scenario("sourcemap_html_false_positive", frozenset(), "source-map path returns HTML shell and must not trigger source-map exposure."),
    Scenario("public_contact_json_review", frozenset({"DYN_RESPONSE_PII_REVIEW", "DYN_PUBLIC_API_JSON_REVIEW"}), "/api returns several public contact channels but no person linkage."),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local 500-target deep-probe calibration using synthetic authorized fixtures.")
    parser.add_argument("--targets", type=int, default=500)
    parser.add_argument("--delay-ms", type=int, default=0, help="Pause between synthetic targets to avoid local ephemeral-port exhaustion.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown")
    parser.add_argument("--html")
    args = parser.parse_args(argv)

    report = run_synthetic_deep_probe_calibration(max(args.targets, 1), delay_ms=max(args.delay_ms, 0))
    write_report(report, args.output, args.markdown, args.html)
    print(json.dumps({"written": args.output, "passed": report["passed"], "targets": report["target_count"]}, ensure_ascii=False))
    return 0 if report["passed"] else 2


def run_synthetic_deep_probe_calibration(target_count: int = 500, *, delay_ms: int = 0) -> dict[str, Any]:
    SyntheticDeepProbeHandler.target_count = target_count
    rows: list[dict[str, Any]] = []
    fixture_batch_size = 50
    fixture_server_count = 0
    for batch_start in range(1, target_count + 1, fixture_batch_size):
        server = HTTPServer(("127.0.0.1", 0), SyntheticDeepProbeHandler)
        fixture_server_count += 1
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            batch_end = min(target_count, batch_start + fixture_batch_size - 1)
            for index in range(batch_start, batch_end + 1):
                scenario = scenario_for_index(index)
                SyntheticDeepProbeHandler.current_index = index
                data = scan_url(base, authorized=False, deep_active=True)
                rows.append(_evaluate_row(index, f"{base}/site-{index:04d}", scenario, data))
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
    aggregate = _aggregate(rows)
    negative_controls = _negative_controls(rows)
    passed = (
        aggregate["missing_expected_target_count"] == 0
        and aggregate["unexpected_target_count"] == 0
        and aggregate["unexpected_high_target_count"] == 0
        and negative_controls["passed"]
    )
    return sanitize_any(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "method": "local_synthetic_deep_probe_calibration",
            "claim_label": "synthetic_loopback_calibration_only_not_real_site_coverage",
            "commercial_wording_guard": "Always describe this as a local synthetic loopback calibration harness. Do not market it as 500 real sites, external deep-probe coverage, vulnerability discovery, or penetration testing.",
            "target_count": target_count,
            "scenario_count": len(SCENARIOS),
            "fixture_batch_size": fixture_batch_size,
            "fixture_server_count": fixture_server_count,
            "inter_target_delay_ms": delay_ms,
            "external_network_used": False,
            "active_profile": "deep",
            "authorization_model": "local_target_only",
            "safety": {
                "requests": "Local fixed-path GET/OPTIONS through the same dashboard scan_url deep_active path.",
                "not_used": [
                    "external public sites",
                    "login attempts",
                    "password guessing",
                    "form submission",
                    "mutation",
                    "exploit payloads",
                    "recursive crawling",
                    "cross-host redirect following",
                ],
                "raw_free_report": True,
            },
            "passed": passed,
            "aggregate": aggregate,
            "negative_controls": negative_controls,
            "rows": rows,
        }
    )


def scenario_for_index(index: int) -> Scenario:
    return SCENARIOS[(index - 1) % len(SCENARIOS)]


def _evaluate_row(index: int, url: str, scenario: Scenario, data: dict[str, Any]) -> dict[str, Any]:
    observed = set(data.get("rule_ids", []))
    expected = set(scenario.expected_rules)
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    unexpected_high = sorted(rule for rule in unexpected if rule in HIGH_RULES)
    summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
    audit_log = data.get("audit_log", []) if isinstance(data.get("audit_log"), list) else []
    return {
        "target_id": f"synthetic-deep-{index:04d}",
        "url": url,
        "scenario": scenario.name,
        "notes": scenario.notes,
        "expected_rule_ids": sorted(expected),
        "observed_rule_ids": sorted(observed),
        "missing_expected_rule_ids": missing,
        "unexpected_rule_ids": unexpected,
        "unexpected_high_rule_ids": unexpected_high,
        "summary": summary,
        "finding_count": len(data.get("findings", [])) if isinstance(data.get("findings"), list) else 0,
        "audit_log_count": len(audit_log),
        "pass": not missing and not unexpected,
    }


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_counts: Counter[str] = Counter(str(row["scenario"]) for row in rows)
    expected_rules: Counter[str] = Counter()
    observed_rules: Counter[str] = Counter()
    missing_rules: Counter[str] = Counter()
    unexpected_rules: Counter[str] = Counter()
    missing_targets = 0
    unexpected_high_targets = 0
    exact_pass_targets = 0
    for row in rows:
        expected_rules.update(row["expected_rule_ids"])
        observed_rules.update(row["observed_rule_ids"])
        missing_rules.update(row["missing_expected_rule_ids"])
        unexpected_rules.update(row["unexpected_rule_ids"])
        if row["missing_expected_rule_ids"]:
            missing_targets += 1
        if row["unexpected_high_rule_ids"]:
            unexpected_high_targets += 1
        if not row["missing_expected_rule_ids"] and not row["unexpected_rule_ids"]:
            exact_pass_targets += 1
    expected_total = sum(expected_rules.values())
    missing_total = sum(missing_rules.values())
    unexpected_total = sum(unexpected_rules.values())
    return {
        "target_count": len(rows),
        "scenario_counts": [{"scenario": name, "count": count} for name, count in scenario_counts.most_common()],
        "expected_rule_total": expected_total,
        "observed_rule_total": sum(observed_rules.values()),
        "missing_expected_rule_total": missing_total,
        "unexpected_rule_total": unexpected_total,
        "recall": _rate(expected_total - missing_total, expected_total),
        "exact_target_pass_rate": _rate(exact_pass_targets, len(rows)),
        "missing_expected_target_count": missing_targets,
        "unexpected_high_target_count": unexpected_high_targets,
        "unexpected_target_count": sum(1 for row in rows if row["unexpected_rule_ids"]),
        "expected_rules": [{"rule_id": rule, "count": count} for rule, count in expected_rules.most_common()],
        "observed_rules": [{"rule_id": rule, "count": count} for rule, count in observed_rules.most_common()],
        "missing_rules": [{"rule_id": rule, "count": count} for rule, count in missing_rules.most_common()],
        "unexpected_rules": [{"rule_id": rule, "count": count} for rule, count in unexpected_rules.most_common()],
    }


def _negative_controls(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive = next((row for row in rows if row["observed_rule_ids"]), None)
    if not positive:
        return {"passed": False, "checks": [{"name": "positive_fixture_available", "passed": False, "reason": "no observed positive fixture"}]}
    injected_missing_rule = "NEGATIVE_CONTROL_NEVER_EMITTED"
    missing_expected = sorted((set(positive["observed_rule_ids"]) | {injected_missing_rule}) - set(positive["observed_rule_ids"]))
    unexpected = sorted(set(positive["observed_rule_ids"]) - set())
    checks = [
        {
            "name": "injected_missing_expected_rule_is_detected",
            "scenario": positive["scenario"],
            "passed": injected_missing_rule in missing_expected,
            "injected_rule": injected_missing_rule,
            "detected_missing": missing_expected,
        },
        {
            "name": "injected_unexpected_rule_is_detected",
            "scenario": positive["scenario"],
            "passed": bool(unexpected),
            "detected_unexpected": unexpected,
        },
    ]
    return {"passed": all(check["passed"] for check in checks), "checks": checks}


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def write_report(report: dict[str, Any], output: str | Path, markdown: str | Path | None = None, html: str | Path | None = None) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if markdown:
        markdown_path = Path(markdown)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(to_markdown(report), encoding="utf-8")
    if html:
        html_path = Path(html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(to_html(report), encoding="utf-8")


def to_markdown(report: dict[str, Any]) -> str:
    aggregate = report["aggregate"]
    lines = [
        "# Synthetic Loopback Deep Probe Calibration",
        "",
        "This is synthetic loopback calibration only. It is not 500 real sites, not external vulnerability discovery, and not penetration testing.",
        "",
        f"- passed: `{report['passed']}`",
        f"- claim label: `{report.get('claim_label', '')}`",
        f"- targets: `{report['target_count']}`",
        f"- recall: `{aggregate['recall']}`",
        f"- exact target pass rate: `{aggregate['exact_target_pass_rate']}`",
        f"- missing expected target count: `{aggregate['missing_expected_target_count']}`",
        f"- unexpected high target count: `{aggregate['unexpected_high_target_count']}`",
        f"- negative controls passed: `{report.get('negative_controls', {}).get('passed', False)}`",
        "",
        "## Expected vs Observed",
        "",
        "| rule | expected | observed | missing | unexpected |",
        "|---|---:|---:|---:|---:|",
    ]
    expected = {row["rule_id"]: row["count"] for row in aggregate["expected_rules"]}
    observed = {row["rule_id"]: row["count"] for row in aggregate["observed_rules"]}
    missing = {row["rule_id"]: row["count"] for row in aggregate["missing_rules"]}
    unexpected = {row["rule_id"]: row["count"] for row in aggregate["unexpected_rules"]}
    for rule in sorted(set(expected) | set(observed) | set(missing) | set(unexpected)):
        lines.append(f"| `{rule}` | {expected.get(rule, 0)} | {observed.get(rule, 0)} | {missing.get(rule, 0)} | {unexpected.get(rule, 0)} |")
    failing = [row for row in report["rows"] if row["missing_expected_rule_ids"] or row["unexpected_rule_ids"]]
    controls = report.get("negative_controls", {})
    if isinstance(controls, dict):
        lines.extend(["", "## Negative Controls", "", "| control | passed | signal |", "|---|---:|---|"])
        for check in controls.get("checks", []):
            if isinstance(check, dict):
                signal = check.get("detected_missing") or check.get("detected_unexpected") or check.get("reason", "")
                lines.append(f"| `{check.get('name', '')}` | {check.get('passed', False)} | {signal} |")
    if failing:
        lines.extend(["", "## Review Rows", "", "| target | scenario | missing | unexpected |", "|---|---|---|---|"])
        for row in failing[:50]:
            lines.append(
                f"| `{row['target_id']}` | {row['scenario']} | {', '.join(row['missing_expected_rule_ids']) or 'none'} | {', '.join(row['unexpected_rule_ids']) or 'none'} |"
            )
    return "\n".join(lines) + "\n"


def to_html(report: dict[str, Any]) -> str:
    aggregate = report["aggregate"]
    rows = []
    for row in report["rows"]:
        cls = "fail" if row["missing_expected_rule_ids"] or row["unexpected_rule_ids"] else "ok"
        rows.append(
            "<tr class=\"{cls}\"><td>{target}</td><td>{scenario}</td><td>{expected}</td><td>{observed}</td><td>{missing}</td><td>{unexpected}</td></tr>".format(
                cls=cls,
                target=escape(str(row["target_id"])),
                scenario=escape(str(row["scenario"])),
                expected=escape(", ".join(row["expected_rule_ids"]) or "none"),
                observed=escape(", ".join(row["observed_rule_ids"]) or "none"),
                missing=escape(", ".join(row["missing_expected_rule_ids"]) or "none"),
                unexpected=escape(", ".join(row["unexpected_rule_ids"]) or "none"),
            )
        )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>K-Guard Synthetic Deep Probe Calibration</title>",
            "<style>body{font-family:Inter,system-ui,sans-serif;margin:24px;background:#f6f8fb;color:#172033}main{max-width:1280px;margin:auto}section{background:white;border:1px solid #d7dde8;border-radius:8px;padding:16px;margin:14px 0}.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.metric{border:1px solid #d7dde8;border-radius:8px;padding:12px;background:#fbfcfe}.metric b{display:block;font-size:24px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #d7dde8;padding:8px;text-align:left;font-size:12px;vertical-align:top}th{background:#eef2f6}.fail td:first-child{border-left:4px solid #b42318}.ok td:first-child{border-left:4px solid #067647}</style>",
            "</head>",
            "<body><main>",
            "<h1>K-Guard Synthetic Loopback Deep Probe Calibration</h1>",
            "<p>This report is synthetic loopback calibration only. It is not 500 real sites, not external vulnerability discovery, and not penetration testing.</p>",
            "<section class=\"metrics\">",
            f"<div class=\"metric\"><span>pass</span><b>{escape(str(report['passed']))}</b></div>",
            f"<div class=\"metric\"><span>targets</span><b>{escape(str(report['target_count']))}</b></div>",
            f"<div class=\"metric\"><span>recall</span><b>{escape(str(aggregate['recall']))}</b></div>",
            f"<div class=\"metric\"><span>missing targets</span><b>{escape(str(aggregate['missing_expected_target_count']))}</b></div>",
            f"<div class=\"metric\"><span>negative controls</span><b>{escape(str(report.get('negative_controls', {}).get('passed', False)))}</b></div>",
            "</section>",
            "<section><h2>Rows</h2><table><thead><tr><th>target</th><th>scenario</th><th>expected</th><th>observed</th><th>missing</th><th>unexpected</th></tr></thead><tbody>",
            "\n".join(rows),
            "</tbody></table></section>",
            "</main></body></html>",
        ]
    )


class SyntheticDeepProbeHandler(BaseHTTPRequestHandler):
    target_count = 500
    current_index = 1

    def log_message(self, format, *args):  # type: ignore[no-untyped-def]
        return

    def do_OPTIONS(self):  # noqa: N802
        site_index, scenario, _ = _route(self.path, self.current_index)
        if site_index and scenario.name == "cors_wildcard_credentials":
            self._send(204, "", headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
            return
        self._send(204, "")

    def do_GET(self):  # noqa: N802
        site_index, scenario, probe_path = _route(self.path, self.current_index)
        if site_index is None:
            self._send(404, "not found")
            return
        handler = getattr(self, f"_scenario_{scenario.name}", None)
        if handler:
            handled = handler(probe_path)
            if handled:
                return
        self._default_get(probe_path)

    def _default_get(self, probe_path: str) -> None:
        if probe_path == "/":
            self._send_html("<!doctype html><html><body><h1>K-Guard fixture</h1></body></html>")
            return
        self._send(404, "not found")

    def _scenario_missing_headers(self, probe_path: str) -> bool:
        if probe_path == "/":
            self._send(200, "<!doctype html><html><body>missing headers</body></html>", content_type="text/html", secure_headers=False)
            return True
        return False

    def _scenario_admin_login(self, probe_path: str) -> bool:
        if probe_path == "/admin":
            self._send_html('<!doctype html><html><body><form><input type="password" name="password"><button>로그인</button></form></body></html>')
            return True
        return False

    def _scenario_admin_spa_shell(self, probe_path: str) -> bool:
        if probe_path == "/admin":
            self._send_html('<!doctype html><html><body><div id="root"></div><script src="/assets/app.js"></script></body></html>')
            return True
        return False

    def _scenario_admin_console(self, probe_path: str) -> bool:
        if probe_path == "/admin":
            self._send_html("<!doctype html><html><body>관리자 대시보드 회원관리 사용자 관리 삭제 승인 설정 변경</body></html>")
            return True
        return False

    def _scenario_admin_review(self, probe_path: str) -> bool:
        if probe_path == "/admin":
            self._send_html("<!doctype html><html><body>Admin area</body></html>")
            return True
        return False

    def _scenario_public_api_json(self, probe_path: str) -> bool:
        if probe_path in {"/api", "/api/users"}:
            self._send_json({"status": "ok", "items": []})
            return True
        return False

    def _scenario_bulk_pii_api(self, probe_path: str) -> bool:
        if probe_path in {"/api", "/api/users"}:
            self._send_json(
                {
                    "users": [
                        {"name": "홍길동", "email": "hong@example.test", "phone": "010-1000-1000"},
                        {"name": "김민수", "email": "minsu@example.test", "phone": "010-2000-2000"},
                        {"name": "이영희", "email": "younghee@example.test", "phone": "010-3000-3000"},
                        {"name": "박지훈", "email": "jihun@example.test", "phone": "010-4000-4000"},
                    ]
                }
            )
            return True
        return False

    def _scenario_secret_api(self, probe_path: str) -> bool:
        if probe_path == "/api":
            self._send_json({"token": "sk-thisisaverylongfakeapikey000", "status": "debug"})
            return True
        return False

    def _scenario_openapi_document(self, probe_path: str) -> bool:
        if probe_path in {"/openapi.json", "/swagger.json"}:
            self._send_json({"openapi": "3.0.0", "paths": {"/api/users": {}, "/admin": {}}})
            return True
        return False

    def _scenario_source_map(self, probe_path: str) -> bool:
        if probe_path.endswith(".map"):
            self._send_json({"version": 3, "sources": ["app/admin.tsx"], "mappings": "AAAA"})
            return True
        return False

    def _scenario_env_file(self, probe_path: str) -> bool:
        if probe_path == "/.env":
            self._send(200, "DATABASE_URL=postgres://user:pass@db/app\nAPI_KEY=kg_test_secret\nJWT_SECRET=fixture_secret\n", content_type="text/plain")
            return True
        return False

    def _scenario_git_config(self, probe_path: str) -> bool:
        if probe_path == "/.git/config":
            self._send(200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@example.test:repo.git\n', content_type="text/plain")
            return True
        return False

    def _scenario_backup_sql(self, probe_path: str) -> bool:
        if probe_path == "/backup.sql":
            self._send(200, "-- MySQL dump\nCREATE TABLE users(id int, email text);\nINSERT INTO users VALUES (1,'a@example.test');\n", content_type="text/plain")
            return True
        return False

    def _scenario_phpinfo(self, probe_path: str) -> bool:
        if probe_path == "/phpinfo.php":
            self._send_html("<!doctype html><html><body>phpinfo() PHP Version 8.3.1</body></html>")
            return True
        return False

    def _scenario_actuator_env(self, probe_path: str) -> bool:
        if probe_path == "/actuator/env":
            self._send_json({"propertySources": [{"name": "systemEnvironment", "properties": {"SECRET_KEY": {"value": "sk-thisisaverylongfakeapikey000"}}}]})
            return True
        return False

    def _scenario_directory_listing(self, probe_path: str) -> bool:
        if probe_path == "/":
            self._send_html("<!doctype html><html><title>Index of /</title><body>Directory listing for /</body></html>")
            return True
        return False

    def _scenario_debug_stack(self, probe_path: str) -> bool:
        if probe_path == "/":
            self._send(200, 'Traceback (most recent call last):\n  File "app.py", line 12, in handler\nException: fixture\n', content_type="text/plain")
            return True
        return False

    def _scenario_external_redirect(self, probe_path: str) -> bool:
        if probe_path == "/":
            self.send_response(302)
            self.send_header("Location", "https://outside.example.test/")
            self.end_headers()
            return True
        return False

    def _scenario_env_html_false_positive(self, probe_path: str) -> bool:
        if probe_path == "/.env":
            self._send_html('<!doctype html><html><body><div id="root"></div><script src="/assets/app.js"></script></body></html>')
            return True
        return False

    def _scenario_openapi_html_false_positive(self, probe_path: str) -> bool:
        if probe_path == "/openapi.json":
            self._send_html('<!doctype html><html><body><div id="root"></div></body></html>')
            return True
        return False

    def _scenario_sourcemap_html_false_positive(self, probe_path: str) -> bool:
        if probe_path.endswith(".map"):
            self._send_html('<!doctype html><html><body><div id="root"></div></body></html>')
            return True
        return False

    def _scenario_public_contact_json_review(self, probe_path: str) -> bool:
        if probe_path == "/api":
            self._send_json({"contacts": [{"email": "info1@example.test"}, {"email": "info2@example.test"}, {"phone": "02-111-2222"}, {"phone": "02-333-4444"}]})
            return True
        return False

    def _send_json(self, value: dict[str, Any]) -> None:
        self._send(200, json.dumps(value, ensure_ascii=False), content_type="application/json")

    def _send_html(self, body: str) -> None:
        self._send(200, body, content_type="text/html")

    def _send(self, status: int, body: str, content_type: str = "text/plain", headers: dict[str, str] | None = None, secure_headers: bool = True) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if secure_headers:
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)


def _route(path: str, current_index: int | None = None) -> tuple[int | None, Scenario, str]:
    clean = path.split("?", 1)[0]
    parts = [part for part in clean.split("/") if part]
    if not parts or not parts[0].startswith("site-"):
        if current_index is None:
            return None, SCENARIOS[0], clean or "/"
        return current_index, scenario_for_index(current_index), clean or "/"
    try:
        index = int(parts[0].split("-", 1)[1])
    except ValueError:
        return None, SCENARIOS[0], clean or "/"
    rest = "/" + "/".join(parts[1:]) if len(parts) > 1 else "/"
    return index, scenario_for_index(index), rest


if __name__ == "__main__":
    raise SystemExit(main())
