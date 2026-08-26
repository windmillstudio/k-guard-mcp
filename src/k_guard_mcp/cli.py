from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

from k_guard_mcp.access_policy import AccessPolicyController
from k_guard_mcp.analyzers import DEFAULT_SEMGREP_PROFILE, SemgrepAnalyzerAdapter
from k_guard_mcp.benchmarking import run_field_benchmark, write_benchmark_report, write_benchmark_template
from k_guard_mcp.benchmark_adapters import run_owasp_python_benchmark, run_public_app_smoke
from k_guard_mcp.control_validation import run_control_validation
from k_guard_mcp.data_release import (
    MCP_INTERCEPT_REPORT_PRODUCER,
    MCP_INTERCEPT_REPORT_SCHEMA,
    build_mcp_interceptor_release_binding,
    mcp_interceptor_evidence_artifacts,
    run_data_release_gate,
)
from k_guard_mcp.dynamic import ALLOWED_HOSTS
from k_guard_mcp.experience import apply_guardian_experience
from k_guard_mcp.field_campaign import write_field_app_roster_template, write_field_campaign_status_report
from k_guard_mcp.field_validation import (
    run_field_validation,
    sign_field_validation_inputs,
    write_field_preregistration,
    write_field_review_queue,
    write_field_validation_templates,
)
from k_guard_mcp.guardian import build_guardian_gate, refresh_guardian_evidence_bundle, run_guardian_audit, write_guardian_manifest_template, write_guardian_report
from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, evidence_hash, evidence_hash_scheme, uses_public_evidence_key
from k_guard_mcp.installer import CLIENT_CHOICES, PROFILE_CHOICES, doctor as doctor_installation, format_doctor_text, format_install_text, install as install_clients
from k_guard_mcp.language_validation import DEFAULT_LANGUAGE_VALIDATION_PACK, run_language_validation_pack
from k_guard_mcp.mcp_proxy import run_stdio_proxy
from k_guard_mcp.mcp_http_proxy import DEFAULT_ALLOWED_ORIGINS, McpHttpProxySettings, create_mcp_http_proxy_app
from k_guard_mcp.mutation_harness import apply_mutation_plan, evaluate_mutation_pack, write_mutation_plan_template
from k_guard_mcp.provenance import evidence_bundle
from k_guard_mcp.reports import has_findings_at_or_above, to_json, to_markdown, write_flow_html, write_flow_svg, write_json, write_markdown, write_sarif
from k_guard_mcp.runtime_validation import run_mcp_http_runtime_validation
from k_guard_mcp.redaction import redact_text, redaction_token, sanitize_any
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.sca import SoftwareCompositionAnalyzer
from k_guard_mcp.scoreboard import evaluate_fixture_corpus
from k_guard_mcp.session import SessionMaterial, load_session_material
from k_guard_mcp.suppression import SUPPRESSION_FIELDS, apply_suppressions_to_guardian_report, apply_suppressions_to_result, write_suppression_template
from k_guard_mcp.validation import run_validation_review, write_validation_review_template


_REDACTION_TOKEN_RE = re.compile(r"<redacted:[A-Z_]+:[0-9a-f]{12}>")


def _configure_windows_utf8_streams() -> None:
    """Keep Korean CLI output UTF-8 when Windows redirects stdout/stderr."""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    _configure_windows_utf8_streams()
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    proxy_invocation = bool(effective_argv and effective_argv[0] in {"mcp-proxy", "mcp-http-proxy"})
    try:
        return _main_impl(argv)
    except Exception as exc:
        print(
            json.dumps({"error": "K_GUARD_COMMAND_FAILED", "message": redact_text(str(exc))}, ensure_ascii=False),
            file=sys.stderr if proxy_invocation else sys.stdout,
        )
        return 1


def _main_impl(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="k-guard",
        description="안경선배: 바이브코딩 결과물을 출하 전에 검수하는 한국 특화 MCP 감사관.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="지원하는 AI 코딩 클라이언트에 안경선배를 연결합니다.")
    install_parser.add_argument("--client", choices=CLIENT_CHOICES, default="auto")
    install_parser.add_argument("--profile", choices=PROFILE_CHOICES, default="workspace")
    install_parser.add_argument("--workspace", metavar="PATH", help="Bind audits to this existing non-link directory (default: invocation cwd).")
    install_parser.add_argument("--dry-run", action="store_true", help="Show a secret-free plan without changing files or client settings.")
    install_parser.add_argument("--json", action="store_true", help="Print the machine-readable secret-free installation report.")

    doctor_parser = subparsers.add_parser("doctor", help="설치, 비공개 런처, MCP 연결 상태를 진단합니다.")
    doctor_parser.add_argument("--client", choices=CLIENT_CHOICES, default="auto")
    doctor_parser.add_argument("--json", action="store_true", help="Print the secret-free Korean status report as JSON.")

    scan_parser = subparsers.add_parser("scan", help="Scan a workspace or file.")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--no-flow", action="store_true")
    scan_parser.add_argument("--json")
    scan_parser.add_argument("--markdown")
    scan_parser.add_argument("--sarif")
    scan_parser.add_argument("--suppressions", help="Fail-closed CSV policy. Release waivers require app/profile/scope/target binding plus fingerprint, owner, reason, and future expiry.")
    scan_parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="Exit with code 3 if findings exist at or above this severity.")

    text_parser = subparsers.add_parser("text", help="Scan text from stdin.")
    text_parser.add_argument("--json", action="store_true")

    probe_parser = subparsers.add_parser("probe", help="Safely probe a localhost or explicitly authorized external HTTP app.")
    probe_parser.add_argument("base_url")
    probe_parser.add_argument("--json", action="store_true")
    probe_parser.add_argument(
        "--session-file",
        help="Short-lived JSON session bound to the exact target origin; may include an identity_assertion response digest.",
    )
    probe_parser.add_argument("--deep-active", action="store_true", help="Run a bounded authorized deep probe for common exposed env/git/backup/debug paths. No login, mutation, fuzzing, or exploit payloads.")
    probe_parser.add_argument("--allow-external", action="store_true", help="Confirm this external target is owned, partner-approved, or in bug-bounty scope.")
    probe_parser.add_argument("--authorization-note", default="", help="Short raw-free note describing the authority to probe this external target.")

    flow_parser = subparsers.add_parser("flow", help="Build an EXPERIMENTAL heuristic data-flow risk map.")
    flow_parser.add_argument("path")
    flow_parser.add_argument("--json", action="store_true")
    flow_parser.add_argument("--svg")
    flow_parser.add_argument("--html")

    observe_parser = subparsers.add_parser("observe-mcp", help="Observe MCP runtime/proxy JSONL events without storing raw values.")
    observe_parser.add_argument("--events", help="JSONL or JSON array file. Reads stdin when omitted.")
    observe_parser.add_argument("--json", action="store_true")

    intercept_parser = subparsers.add_parser("mcp-intercept", help="Apply MCP runtime block/redact policy before forwarding events.")
    intercept_parser.add_argument("--events", help="JSONL or JSON array file. Reads stdin when omitted.")
    intercept_parser.add_argument("--forwarded-output", required=True, help="Write enforced JSONL events: blocked events become stubs and redacted events have sensitive fields masked.")
    intercept_parser.add_argument("--report", required=True, help="Write a raw-free JSON report describing interceptor decisions.")
    intercept_parser.add_argument("--app-id", default="", help="Release app identifier. Required when this report will qualify for data-release-gate.")
    intercept_parser.add_argument("--session-id", default="", help="Runtime review session identifier. Required when this report will qualify for data-release-gate.")
    intercept_parser.add_argument("--guardian-report", default="", help="Current canonical Guardian report to bind. Required when this report will qualify for data-release-gate.")
    intercept_parser.add_argument("--fail-on-block", action="store_true", help="Exit with code 3 when any event was blocked.")

    proxy_parser = subparsers.add_parser("mcp-proxy", help="Run a live stdio JSONL proxy that enforces policy in both client-to-server and server-to-client directions.")
    proxy_parser.add_argument("--report", help="Optional raw-free JSON policy report path. Protocol output remains on stdout.")
    proxy_parser.add_argument(
        "--receipt-log",
        help="Optional HMAC-chained raw-free mediation receipt JSONL. Defaults to <report>.receipts.jsonl when --report is set.",
    )
    proxy_parser.add_argument(
        "--response-timeout",
        type=float,
        default=30.0,
        help="Fail closed when an upstream request has no response within this many seconds (default: 30).",
    )
    proxy_parser.add_argument("--access-policy", help="Strict JSON JIT/JEA policy. Enables default-deny agent authorization.")
    proxy_parser.add_argument("--access-key-env", default="K_GUARD_AGENT_JWT_KEY", help="Environment variable containing the HS256 signing key.")
    proxy_parser.add_argument("--access-token-env", default="K_GUARD_AGENT_TOKEN", help="Environment variable containing the short-lived stdio grant.")
    proxy_parser.add_argument("--access-app-id", default="")
    proxy_parser.add_argument("--access-session-id", default="")
    proxy_parser.add_argument("--access-purpose", default="")
    proxy_parser.add_argument("--access-audit-log", help="Required append-only HMAC-chained JSONL audit log when access policy is enabled.")
    proxy_parser.add_argument("--allow-env", action="append", default=[], help="Explicit upstream environment variable allowlist entry.")
    proxy_parser.add_argument("--max-line-bytes", type=int, default=1024 * 1024)
    proxy_parser.add_argument("--max-stream-bytes", type=int, default=64 * 1024 * 1024)
    proxy_parser.add_argument("--max-messages", type=int, default=100_000)
    proxy_parser.add_argument("upstream", nargs=argparse.REMAINDER, help="Upstream argv after '--'; no shell is used.")

    http_proxy_parser = subparsers.add_parser(
        "mcp-http-proxy",
        help="Run the fail-closed Streamable HTTP MCP proxy on a loopback interface.",
    )
    http_proxy_parser.add_argument("--upstream", required=True, help="Fixed upstream Streamable HTTP MCP endpoint.")
    http_proxy_parser.add_argument("--host", choices=("127.0.0.1", "::1", "localhost"), default="127.0.0.1")
    http_proxy_parser.add_argument("--port", type=int, default=8765)
    http_proxy_parser.add_argument("--endpoint", default="/mcp")
    http_proxy_parser.add_argument("--allowed-origin", action="append", dest="allowed_origins")
    http_proxy_parser.add_argument("--report", required=True, help="Continuously write the raw-free proxy report.")
    http_proxy_parser.add_argument(
        "--receipt-log",
        help="Optional HMAC-chained raw-free mediation receipt JSONL. Defaults to <report>.receipts.jsonl.",
    )
    http_proxy_parser.add_argument("--timeout", type=float, default=30.0)
    http_proxy_parser.add_argument(
        "--forward-authorization",
        action="store_true",
        help="Explicitly forward the incoming Authorization header to the fixed upstream.",
    )
    http_proxy_parser.add_argument("--require-origin", action="store_true")
    http_proxy_parser.add_argument("--access-policy", help="Strict JSON JIT/JEA policy. Bearer grants are validated at the proxy boundary.")
    http_proxy_parser.add_argument("--access-key-env", default="K_GUARD_AGENT_JWT_KEY")
    http_proxy_parser.add_argument("--access-app-id", default="")
    http_proxy_parser.add_argument("--access-session-id", default="")
    http_proxy_parser.add_argument("--access-purpose", default="")
    http_proxy_parser.add_argument("--access-audit-log", help="Required append-only HMAC-chained JSONL audit log when access policy is enabled.")
    http_proxy_parser.add_argument("--max-sse-stream-bytes", type=int, default=16 * 1024 * 1024)
    http_proxy_parser.add_argument("--max-sse-events", type=int, default=10_000)
    http_proxy_parser.add_argument("--max-sse-seconds", type=float, default=300.0)
    http_proxy_parser.add_argument("--max-sse-streams", type=int, default=32)

    access_template_parser = subparsers.add_parser("access-policy-template", help="Write a strict default-deny agent JIT/JEA policy template.")
    access_template_parser.add_argument("--output", required=True)

    grant_parser = subparsers.add_parser("agent-grant", help="Mint a short-lived signed agent grant into a private file.")
    grant_parser.add_argument("--policy", required=True)
    grant_parser.add_argument("--output", required=True)
    grant_parser.add_argument("--key-env", default="K_GUARD_AGENT_JWT_KEY")
    grant_parser.add_argument("--app-id", required=True)
    grant_parser.add_argument("--session-id", required=True)
    grant_parser.add_argument("--purpose", required=True)
    grant_parser.add_argument("--subject", required=True)
    grant_parser.add_argument("--role", action="append", required=True)
    grant_parser.add_argument("--method", action="append", required=True)
    grant_parser.add_argument("--tool", action="append", default=[])
    grant_parser.add_argument("--resource", action="append", default=[])
    grant_parser.add_argument("--ttl", type=int, default=300)
    grant_parser.add_argument("--max-calls", type=int, default=100)

    control_validation_parser = subparsers.add_parser(
        "control-validate",
        help="Run the repeatable JIT/JEA and database AST/RBAC/isolation control pack.",
    )
    control_validation_parser.add_argument("--output", required=True)

    runtime_validation_parser = subparsers.add_parser(
        "runtime-validate",
        help="Run the repeated Streamable HTTP, JIT/JEA, lifecycle, SSE, and audit-chain matrix.",
    )
    runtime_validation_parser.add_argument("--output", required=True)

    deep_parser = subparsers.add_parser(
        "deep-analyze",
        help="Run the bounded, offline Semgrep deep profile and emit a raw-free analyzer report.",
    )
    deep_parser.add_argument("path")
    deep_parser.add_argument("--output", required=True)
    deep_parser.add_argument(
        "--semgrep-executable",
        default=os.environ.get("K_GUARD_SEMGREP_EXECUTABLE", "semgrep"),
        help="Semgrep executable path; defaults to K_GUARD_SEMGREP_EXECUTABLE or PATH.",
    )
    deep_parser.add_argument("--profile", default=str(DEFAULT_SEMGREP_PROFILE))
    deep_parser.add_argument("--timeout", type=float, default=120.0)

    sca_parser = subparsers.add_parser(
        "sca",
        help="Run bounded lockfile-aware software composition analysis with local ecosystem engines.",
    )
    sca_parser.add_argument("path")
    sca_parser.add_argument("--output", required=True)
    sca_parser.add_argument("--ecosystem", action="append", choices=("python", "npm", "go"))

    language_parser = subparsers.add_parser(
        "language-validate",
        help="Run the pinned nine-language validation pack twice and score TP/FN/FP/TN.",
    )
    language_parser.add_argument("--pack", default=str(DEFAULT_LANGUAGE_VALIDATION_PACK))
    language_parser.add_argument("--output", required=True)
    language_parser.add_argument(
        "--semgrep-executable",
        default=os.environ.get("K_GUARD_SEMGREP_EXECUTABLE", "semgrep"),
    )
    language_parser.add_argument("--timeout", type=float, default=180.0)

    score_parser = subparsers.add_parser("score-corpus", help="Evaluate a fixture corpus and print FP/FN precision/recall scoreboard.")
    score_parser.add_argument("--corpus", required=True)
    score_parser.add_argument("--output")
    score_parser.add_argument("--json", action="store_true")

    owasp_benchmark_parser = subparsers.add_parser(
        "owasp-python-benchmark",
        help="Run the official OWASP Benchmark Python ground-truth adapter twice and write a scoped scorecard.",
    )
    owasp_benchmark_parser.add_argument("--repo", required=True)
    owasp_benchmark_parser.add_argument("--expected-results")
    owasp_benchmark_parser.add_argument("--output-dir", required=True)
    owasp_benchmark_parser.add_argument("--require-ready", action="store_true", help="Exit 3 unless the strict public-benchmark profile passes.")

    public_smoke_parser = subparsers.add_parser(
        "public-app-smoke",
        help="Scan an unlabeled public app twice. This measures coverage and reproducibility, not accuracy.",
    )
    public_smoke_parser.add_argument("path")
    public_smoke_parser.add_argument("--output", required=True)
    public_smoke_parser.add_argument("--require-reproducible", action="store_true")

    mutation_template_parser = subparsers.add_parser("mutation-template", help="Create a copy-only seeded-mutation JSON plan template.")
    mutation_template_parser.add_argument("--output", required=True)

    mutation_apply_parser = subparsers.add_parser("mutation-apply", help="Create disjoint baseline/mutated app copies from an exact JSON mutation plan.")
    mutation_apply_parser.add_argument("--source", required=True)
    mutation_apply_parser.add_argument("--plan", required=True)
    mutation_apply_parser.add_argument("--output", required=True)

    mutation_evaluate_parser = subparsers.add_parser("mutation-evaluate", help="Scan a mutation pack twice and calculate seeded TP/FP/FN evidence.")
    mutation_evaluate_parser.add_argument("--pack", required=True)
    mutation_evaluate_parser.add_argument("--output")

    benchmark_template_parser = subparsers.add_parser("benchmark-template", help="Create a 20/20/10 field benchmark manifest template.")
    benchmark_template_parser.add_argument("--output", required=True)

    benchmark_parser = subparsers.add_parser("benchmark", help="Aggregate K-Guard field benchmark reports by cohort.")
    benchmark_parser.add_argument("--manifest", required=True)
    benchmark_parser.add_argument("--review", help="Optional CSV with target_id,rule_id,verdict for manual FP/TP review.")
    benchmark_parser.add_argument("--output", required=True)
    benchmark_parser.add_argument("--markdown")
    benchmark_parser.add_argument("--html")
    benchmark_parser.add_argument("--run-probes", action="store_true", help="Actually run authorized dynamic probes for manifest rows with mode=probe.")

    guardian_template_parser = subparsers.add_parser("guardian-template", help="Create a korean_senior four-domain Guardian manifest template.")
    guardian_template_parser.add_argument("--output", required=True)

    guardian_parser = subparsers.add_parser("guardian", help="Run a raw-free four-domain Guardian audit over authorized workspace/http/MCP/report targets.")
    guardian_parser.add_argument("--manifest", required=True)
    guardian_parser.add_argument("--output", required=True)
    guardian_parser.add_argument("--markdown")
    guardian_parser.add_argument("--html")
    guardian_parser.add_argument("--previous", help="Optional previous guardian JSON report for drift/new blocker detection.")
    guardian_parser.add_argument("--run-probes", action="store_true", help="Actually run authorized HTTP probes for manifest rows with kind=http.")
    guardian_parser.add_argument("--suppressions", help="CSV suppression policy applied fail-closed before guardian_gate is computed.")
    guardian_parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="Exit with code 3 when guardian targets have findings at or above this severity.")
    guardian_parser.add_argument("--language-validation-report", help="Operator-signed nine-language development validation report.")
    guardian_parser.add_argument("--mcp-http-proxy-report", help="Operator-signed, exercised Streamable HTTP proxy report.")
    guardian_parser.add_argument("--field-validation-report", help="Operator-signed 12-20 app field validation report.")
    guardian_parser.add_argument("--control-validation-report", help="Operator-signed repeated JIT/JEA and database control validation report.")
    guardian_parser.add_argument("--run-sca", action="store_true", help="Authorize local dependency audit engines; they may consult configured vulnerability databases.")
    guardian_parser.add_argument(
        "--semgrep-executable",
        default=os.environ.get("K_GUARD_SEMGREP_EXECUTABLE", "semgrep"),
        help="Semgrep used automatically for the release workspace deep analysis.",
    )

    suppression_template_parser = subparsers.add_parser("suppression-template", help="Create a fail-closed suppression policy CSV template.")
    suppression_template_parser.add_argument("--output", required=True)

    validation_template_parser = subparsers.add_parser("validation-template", help="Create the legacy single-review candidate adjudication CSV template.")
    validation_template_parser.add_argument("--output", required=True)

    validation_parser = subparsers.add_parser("validation-report", help="Aggregate legacy candidate labels. This does not establish field recall without ground truth.")
    validation_parser.add_argument("--guardian-report", required=True)
    validation_parser.add_argument("--review", required=True)
    validation_parser.add_argument("--output", required=True)

    field_validation_template_parser = subparsers.add_parser(
        "field-validation-template",
        help="Create dual-review ground-truth and candidate-review CSV templates.",
    )
    field_validation_template_parser.add_argument("--ground-truth-output", required=True)
    field_validation_template_parser.add_argument("--review-output", required=True)

    field_campaign_template_parser = subparsers.add_parser(
        "field-campaign-template",
        help="Create an empty raw-free owned/partner app roster template.",
    )
    field_campaign_template_parser.add_argument("--output", required=True)

    field_campaign_status_parser = subparsers.add_parser(
        "field-campaign-status",
        help="Fail closed unless the owned/partner app roster is ready for preregistration.",
    )
    field_campaign_status_parser.add_argument("--roster", required=True)
    field_campaign_status_parser.add_argument("--output", required=True)

    field_validation_queue_parser = subparsers.add_parser(
        "field-validation-queue",
        help="Export every Guardian high/critical candidate into a dual-review CSV queue.",
    )
    field_validation_queue_parser.add_argument("--guardian-report", required=True)
    field_validation_queue_parser.add_argument("--output", required=True)

    field_preregistration_parser = subparsers.add_parser(
        "field-validation-preregister",
        help="Bind the frozen ground-truth CSV to operator evidence plus a distinct custodian signature before the first Guardian scan.",
    )
    field_preregistration_parser.add_argument("--ground-truth", required=True)
    field_preregistration_parser.add_argument("--roster", required=True)
    field_preregistration_parser.add_argument("--output", required=True)
    field_preregistration_parser.add_argument("--custodian-id", required=True, help="Independent split custodian identity; stored only as a keyed reference.")

    field_sign_parser = subparsers.add_parser(
        "field-validation-sign",
        help="Sign reviewer verdict rows with distinct keys from K_GUARD_FIELD_REVIEWER_HMAC_KEYS.",
    )
    field_sign_parser.add_argument("--ground-truth")
    field_sign_parser.add_argument("--review")

    field_validation_parser = subparsers.add_parser(
        "field-validation-report",
        help="Calculate ground-truth precision, recall, specificity, holdout performance, and repeat-run reproducibility.",
    )
    field_validation_parser.add_argument("--guardian-report", required=True)
    field_validation_parser.add_argument("--repeat-guardian-report", required=True)
    field_validation_parser.add_argument("--ground-truth", required=True)
    field_validation_parser.add_argument("--review", required=True)
    field_validation_parser.add_argument("--preregistration", help="Required for profile=field; must predate the primary Guardian report.")
    field_validation_parser.add_argument("--roster", help="Required for profile=field; must match the preregistered owned/partner roster.")
    field_validation_parser.add_argument("--profile", choices=("field", "benchmark", "mutation", "pilot"), default="field")
    field_validation_parser.add_argument("--output", required=True)

    data_gate_parser = subparsers.add_parser("data-release-gate", help="Fail-closed data shipment gate over Guardian, validation, Korean corpus, and MCP interceptor evidence.")
    data_gate_parser.add_argument("--guardian-report", required=True)
    data_gate_parser.add_argument("--guardian-manifest", required=True)
    data_gate_parser.add_argument("--validation-source-guardian-report", required=True)
    data_gate_parser.add_argument("--validation-repeat-guardian-report", required=True)
    data_gate_parser.add_argument("--validation-report", required=True)
    data_gate_parser.add_argument("--validation-review", required=True)
    data_gate_parser.add_argument("--validation-ground-truth", required=True)
    data_gate_parser.add_argument("--validation-preregistration", required=True)
    data_gate_parser.add_argument("--validation-roster", required=True)
    data_gate_parser.add_argument("--korean-fixture-corpus", required=True)
    data_gate_parser.add_argument("--korean-corpus-report", required=True)
    data_gate_parser.add_argument("--mcp-intercept-report", required=True)
    data_gate_parser.add_argument("--mcp-forwarded-output", required=True)
    data_gate_parser.add_argument("--output", required=True)
    data_gate_parser.add_argument("--max-validation-fp-rate", type=float, default=0.2)

    feedback_parser = subparsers.add_parser("feedback", help="Append a sanitized false-positive or false-negative report.")
    feedback_parser.add_argument("--type", choices=("fp", "fn"), required=True)
    feedback_parser.add_argument("--rule", required=True)
    feedback_parser.add_argument("--text", required=True)
    feedback_parser.add_argument("--output", required=True)

    feedback_export_parser = subparsers.add_parser("feedback-export", help="Summarize sanitized feedback JSONL for local drift review.")
    feedback_export_parser.add_argument("--input", required=True)
    feedback_export_parser.add_argument("--output", required=True)
    feedback_export_parser.add_argument("--sample-limit", type=int, default=20)
    feedback_export_parser.add_argument("--reviewed", action="store_true", help="Confirm the sanitized summary is approved for local export.")

    args = parser.parse_args(argv)
    if args.command == "install":
        report = install_clients(
            client=args.client,
            profile=args.profile,
            dry_run=args.dry_run,
            workspace=args.workspace,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else format_install_text(report))
        return 0 if report.get("ok") else 2

    if args.command == "doctor":
        report = doctor_installation(client=args.client)
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else format_doctor_text(report))
        return 0 if report.get("ok") else 2

    if args.command == "access-policy-template":
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(_access_policy_template(), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"written": str(output), "schema": "k_guard_agent_access_policy.v1"}, ensure_ascii=False))
        return 0

    if args.command == "agent-grant":
        try:
            key = _required_secret_env(args.key_env)
            controller = AccessPolicyController.from_file(
                args.policy,
                key,
                app_id=args.app_id,
                session_id=args.session_id,
                purpose=args.purpose,
            )
            token = controller.mint_grant(
                subject=args.subject,
                roles=args.role,
                methods=args.method,
                tools=args.tool,
                resources=args.resource,
                ttl_seconds=args.ttl,
                max_calls=args.max_calls,
            )
            _write_private_text(Path(args.output), token + "\n")
        except Exception as exc:
            print(json.dumps({"error": "AGENT_GRANT_FAILED", "detail": redact_text(str(exc))}, ensure_ascii=False))
            return 2
        print(
            json.dumps(
                {
                    "written": args.output,
                    "grant_ref": evidence_hash(token),
                    "ttl_seconds": args.ttl,
                    "max_calls": args.max_calls,
                    "raw_returned": False,
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "mcp-proxy":
        try:
            access_controller = _access_controller_from_args(args)
            access_token = _required_secret_env(args.access_token_env) if access_controller is not None else None
        except Exception as exc:
            print(json.dumps({"error": "ACCESS_POLICY_CONFIGURATION_FAILED", "detail": redact_text(str(exc))}, ensure_ascii=False), file=sys.stderr)
            return 2
        return run_stdio_proxy(
            args.upstream,
            report_path=args.report,
            response_timeout_seconds=args.response_timeout,
            max_line_bytes=args.max_line_bytes,
            max_stream_bytes=args.max_stream_bytes,
            max_messages=args.max_messages,
            allowed_environment_names=tuple(args.allow_env),
            access_controller=access_controller,
            access_token=access_token,
            receipt_log_path=args.receipt_log,
        )

    if args.command == "mcp-http-proxy":
        if not 1 <= args.port <= 65535:
            parser.error("mcp-http-proxy --port must be between 1 and 65535")
        try:
            access_controller = _access_controller_from_args(args)
        except Exception as exc:
            print(json.dumps({"error": "ACCESS_POLICY_CONFIGURATION_FAILED", "detail": redact_text(str(exc))}, ensure_ascii=False), file=sys.stderr)
            return 2
        settings = McpHttpProxySettings(
            endpoint_path=args.endpoint,
            allowed_origins=tuple(args.allowed_origins or DEFAULT_ALLOWED_ORIGINS),
            timeout_seconds=args.timeout,
            forward_authorization=args.forward_authorization,
            require_origin=args.require_origin,
            max_sse_stream_bytes=args.max_sse_stream_bytes,
            max_sse_events=args.max_sse_events,
            max_sse_stream_seconds=args.max_sse_seconds,
            max_concurrent_sse_streams=args.max_sse_streams,
            report_path=args.report,
            receipt_log_path=args.receipt_log,
        )
        app = create_mcp_http_proxy_app(args.upstream, settings, access_controller=access_controller)
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    if args.command == "control-validate":
        report = run_control_validation()
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": str(output),
                    "passed": report["passed"],
                    "case_count": report["case_count"],
                    "repeat_exact": report["repeat"]["exact"],
                },
                ensure_ascii=False,
            )
        )
        return 0 if report["passed"] else 3

    if args.command == "runtime-validate":
        report = run_mcp_http_runtime_validation()
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        validation = report["runtime_validation"]
        print(
            json.dumps(
                {
                    "written": str(output),
                    "passed": report["passed"],
                    "run_count": validation["run_count"],
                    "repeat_exact": validation["repeat_exact"],
                    "matrix": validation["matrix"],
                },
                ensure_ascii=False,
            )
        )
        return 0 if report["passed"] else 3

    if args.command == "deep-analyze":
        run = SemgrepAnalyzerAdapter(
            executable=args.semgrep_executable,
            profile_path=args.profile,
            timeout_seconds=args.timeout,
        ).analyze(args.path)
        report = run.to_report()
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": str(output),
                    "complete": run.complete,
                    "finding_count": len(run.findings),
                    "control_errors": list(run.control_errors),
                    "analyzer_subtype": run.analyzer_subtype,
                },
                ensure_ascii=False,
            )
        )
        return 0 if run.complete else 3

    if args.command == "sca":
        report = SoftwareCompositionAnalyzer().analyze(args.path, ecosystems=args.ecosystem).to_report()
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": str(output),
                    "complete": report["complete"],
                    "passed": report["passed"],
                    "finding_count": report["counts"]["finding_count"],
                    "audited_ecosystems": report["audited_ecosystems"],
                },
                ensure_ascii=False,
            )
        )
        return 0 if report["passed"] else 3

    if args.command == "language-validate":
        report = run_language_validation_pack(
            args.pack,
            SemgrepAnalyzerAdapter(executable=args.semgrep_executable, timeout_seconds=args.timeout),
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": str(output),
                    "complete": report["complete"],
                    "ready": report["ready"],
                    "status": report["status"],
                    "overall": (report.get("metrics") or {}).get("overall", {}),
                },
                ensure_ascii=False,
            )
        )
        return 0 if report["ready"] else 3

    if args.command == "owasp-python-benchmark":
        report = run_owasp_python_benchmark(
            args.repo,
            args.output_dir,
            expected_results_path=args.expected_results,
        )
        print(
            json.dumps(
                {
                    "written": str(Path(args.output_dir) / "benchmark-score.json"),
                    "validation_claim_status": report["validation_claim_status"],
                    "supported_case_count": report["score"]["supported_case_count"],
                    "recall": report["score"]["recall"],
                    "false_positive_rate": report["score"]["false_positive_rate"],
                    "all_candidate_precision": report.get("all_high_critical_candidate_validation", {}).get("rates", {}).get("precision"),
                    "all_candidate_clean_case_false_positive_rate": report.get("all_high_critical_candidate_validation", {}).get("rates", {}).get("false_positive_rate"),
                },
                ensure_ascii=False,
            )
        )
        if args.require_ready and report["validation_claim_status"] != "public_benchmark_ready":
            return 3
        return 0

    if args.command == "public-app-smoke":
        report = run_public_app_smoke(args.path)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": args.output,
                    "claim_status": report["claim_status"],
                    "exact_finding_set_match": report["reproducibility"]["exact_finding_set_match"],
                    "finding_count": report["finding_count"],
                },
                ensure_ascii=False,
            )
        )
        if args.require_reproducible and not report["reproducibility"]["exact_finding_set_match"]:
            return 3
        return 0

    if args.command == "mutation-template":
        write_mutation_plan_template(args.output)
        print(json.dumps({"written": args.output, "schema": "k_guard_mutation_plan.v1"}, ensure_ascii=False))
        return 0

    if args.command == "mutation-apply":
        report = apply_mutation_plan(args.source, args.output, args.plan)
        print(
            json.dumps(
                {
                    "written": str(Path(args.output) / "mutation-report.json"),
                    "mutation_count": report["mutation_count"],
                    "evaluation_status": report["evaluation_status"],
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "mutation-evaluate":
        report = evaluate_mutation_pack(args.pack, args.output)
        destination = Path(args.output) if args.output else Path(args.pack) / "evaluation"
        print(
            json.dumps(
                {
                    "written": str(destination / "mutation-score.json"),
                    "profile": report["profile"],
                    "validation_claim_status": report["validation_claim_status"],
                    "rates": report["rates"],
                },
                ensure_ascii=False,
            )
        )
        return 0

    scanner = KGuardScanner()

    if args.command == "scan":
        result = scanner.scan_workspace(args.path, include_flow=not args.no_flow)
        result = apply_suppressions_to_result(result, args.suppressions)
        if args.json:
            write_json(result, args.json)
        if args.markdown:
            write_markdown(result, args.markdown)
        if args.sarif:
            write_sarif(result, args.sarif)
        print(to_json(result))
        if args.fail_on and has_findings_at_or_above(result, args.fail_on):
            if uses_public_evidence_key():
                print(
                    json.dumps(
                        {
                            "warning": "K_GUARD_PUBLIC_EVIDENCE_KEY_IN_FAIL_ON_MODE",
                            "message": f"{EVIDENCE_HMAC_ENV} is not set; SARIF evidence hashes use the public default key for reproducible local baselines. Set a CI secret for tamper-resistant evidence chains.",
                        },
                        ensure_ascii=False,
                    ),
                    file=sys.stderr,
                )
            return 3
        return 0

    if args.command == "text":
        text = sys.stdin.read()
        result = scanner.scan_text(text, "stdin")
        print(to_json(result) if args.json else to_markdown(result))
        return 0

    if args.command == "probe":
        allowed_hosts = _probe_allowed_hosts(args.base_url, args.allow_external)
        authorization_note = _probe_authorization_note(args.base_url, args.allow_external, args.authorization_note)
        session = _load_session_headers(args.session_file, args.base_url) if args.session_file else None
        result = scanner.probe_http(
            args.base_url,
            session_headers=session.headers if session else None,
            identity_assertion=session.identity_assertion if session else None,
            active_profile="deep" if args.deep_active else "baseline",
            allowed_hosts=allowed_hosts,
            authorization_note=authorization_note,
        )
        print(to_json(result) if args.json else to_markdown(result))
        return 0

    if args.command == "flow":
        result = scanner.build_flow_map(args.path)
        if args.svg:
            write_flow_svg(result, args.svg)
        if args.html:
            write_flow_html(result, args.html)
        print(to_json(result) if args.json else to_markdown(result))
        return 0

    if args.command == "observe-mcp":
        text = Path(args.events).read_text(encoding="utf-8") if args.events else sys.stdin.read()
        result = scanner.observe_mcp_events(text, args.events or "stdin")
        print(to_json(result) if args.json else to_markdown(result))
        return 0

    if args.command == "mcp-intercept":
        text = Path(args.events).read_text(encoding="utf-8") if args.events else sys.stdin.read()
        result, forwarded_events = scanner.enforce_mcp_events(text, args.events or "stdin")
        forwarded_output = Path(args.forwarded_output)
        forwarded_output.parent.mkdir(parents=True, exist_ok=True)
        forwarded_payload = "\n".join(json.dumps(event, ensure_ascii=False) for event in forwarded_events)
        if forwarded_events:
            forwarded_payload += "\n"
        forwarded_output.write_text(forwarded_payload, encoding="utf-8")
        report_data = result.to_dict()
        report_data["schema"] = MCP_INTERCEPT_REPORT_SCHEMA
        report_data["producer"] = MCP_INTERCEPT_REPORT_PRODUCER
        report_data["raw_free"] = True
        runtime_policy = report_data.setdefault("metadata", {}).setdefault("runtime_policy", {})
        interceptor_policy = runtime_policy.setdefault("interceptor", {})
        interceptor_policy["forwarded_output_ref"] = _forwarded_output_ref(forwarded_output, forwarded_payload, len(forwarded_events))
        report_data["release_binding"] = build_mcp_interceptor_release_binding(args.app_id, args.session_id, args.guardian_report)
        report_data["evidence_bundle"] = evidence_bundle(
            "mcp_runtime_interceptor",
            MCP_INTERCEPT_REPORT_PRODUCER,
            mcp_interceptor_evidence_artifacts(report_data, forwarded_output, args.guardian_report),
        )
        report_output = Path(args.report)
        report_output.parent.mkdir(parents=True, exist_ok=True)
        report_output.write_text(json.dumps(sanitize_any(report_data), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        policy = report_data.get("metadata", {}).get("runtime_policy", {})
        interceptor = policy.get("interceptor", {}) if isinstance(policy, dict) else {}
        summary = {
            "forwarded_output": str(forwarded_output),
            "report": str(report_output),
            "event_count": interceptor.get("event_count", 0),
            "parse_error_count": policy.get("parse_error_count", 0),
            "blocked_count": interceptor.get("blocked_count", 0),
            "redacted_count": interceptor.get("redacted_count", 0),
        }
        print(json.dumps(summary, ensure_ascii=False))
        control_failed = int(policy.get("parse_error_count", 0)) > 0
        return 3 if args.fail_on_block and (control_failed or int(interceptor.get("blocked_count", 0)) > 0) else 0

    if args.command == "score-corpus":
        report = evaluate_fixture_corpus(args.corpus, scanner)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json or args.output else _scoreboard_summary(report))
        return 0 if report["passed"] else 4

    if args.command == "benchmark-template":
        write_benchmark_template(args.output)
        print(json.dumps({"written": args.output, "cohorts": {"general": 20, "vibecoded_suspected": 20, "authorized_owned_partner": 10}}, ensure_ascii=False))
        return 0

    if args.command == "benchmark":
        report = run_field_benchmark(args.manifest, review_path=args.review, run_probes=args.run_probes)
        write_benchmark_report(report, args.output, markdown=args.markdown, html=args.html)
        print(json.dumps({"written": args.output, "markdown": args.markdown, "html": args.html, "run_probes": args.run_probes}, ensure_ascii=False))
        return 0

    if args.command == "guardian-template":
        write_guardian_manifest_template(args.output)
        print(json.dumps({"written": args.output, "fields": "authorized target guardian manifest"}, ensure_ascii=False))
        return 0

    if args.command == "guardian":
        report = run_guardian_audit(
            args.manifest,
            previous_report_path=args.previous,
            run_probes=args.run_probes,
            scanner=scanner,
            fail_on_override=args.fail_on,
            semgrep_executable=args.semgrep_executable,
            language_validation_report_path=args.language_validation_report,
            mcp_http_proxy_report_path=args.mcp_http_proxy_report,
            field_validation_report_path=args.field_validation_report,
            control_validation_report_path=args.control_validation_report,
            run_sca=args.run_sca,
        )
        report = apply_suppressions_to_guardian_report(report, args.suppressions)
        gate = _guardian_gate(report, args.fail_on)
        if gate:
            report["guardian_gate"] = gate
        apply_guardian_experience(report)
        refresh_guardian_evidence_bundle(report, args.manifest)
        write_guardian_report(report, args.output, markdown_path=args.markdown, html_path=args.html)
        print(
            json.dumps(
                {
                    "written": args.output,
                    "markdown": args.markdown,
                    "html": args.html,
                    "run_probes": args.run_probes,
                    "blocking_targets": report["summary"]["blocking_target_count"],
                    "guardian_gate": gate,
                    "experience": report.get("experience", {}).get("presentation", report.get("experience", {})),
                },
                ensure_ascii=False,
            )
        )
        return 3 if gate and not gate["passed"] else 0

    if args.command == "suppression-template":
        write_suppression_template(args.output)
        print(json.dumps({"written": args.output, "required_fields": SUPPRESSION_FIELDS}, ensure_ascii=False))
        return 0

    if args.command == "validation-template":
        write_validation_review_template(args.output)
        print(json.dumps({"written": args.output, "verdicts": ["true_positive", "false_positive", "false_negative", "benign", "inconclusive"]}, ensure_ascii=False))
        return 0

    if args.command == "validation-report":
        report = run_validation_review(args.guardian_report, args.review)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"written": args.output, "claim_status": report["claim_status"], "app_count": report["sample"]["app_count"]}, ensure_ascii=False))
        return 0 if report["claim_status"] == "validation_sample_ready" else 3

    if args.command == "field-validation-template":
        write_field_validation_templates(args.ground_truth_output, args.review_output)
        print(
            json.dumps(
                {
                    "ground_truth_written": args.ground_truth_output,
                    "review_written": args.review_output,
                    "profiles": ["field", "benchmark", "mutation", "pilot"],
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "field-campaign-template":
        write_field_app_roster_template(args.output)
        print(json.dumps({"written": args.output, "ready": False, "next": "fill_12_to_20_owned_partner_apps"}, ensure_ascii=False))
        return 0

    if args.command == "field-campaign-status":
        report = write_field_campaign_status_report(args.roster, args.output)
        print(json.dumps({"written": args.output, "ready": report["ready"], "blockers": report["blockers"]}, ensure_ascii=False))
        return 0 if report["ready"] else 3

    if args.command == "field-validation-queue":
        report = write_field_review_queue(args.guardian_report, args.output)
        print(json.dumps({"written": args.output, **report}, ensure_ascii=False))
        return 0

    if args.command == "field-validation-preregister":
        report = write_field_preregistration(
            args.ground_truth,
            args.output,
            custodian_id=args.custodian_id,
            roster_path=args.roster,
        )
        print(
            json.dumps(
                {
                    "written": args.output,
                    "schema": report["schema"],
                    "ground_truth_row_count": report["ground_truth_row_count"],
                    "operator_keyed": report["preregistration_evidence_envelope"]["signature"]["key_mode"] == "operator-keyed",
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "field-validation-sign":
        if not args.ground_truth and not args.review:
            print(
                json.dumps({"error": "field-validation-sign requires --ground-truth and/or --review"}),
                file=sys.stderr,
            )
            return 2
        report = sign_field_validation_inputs(
            ground_truth_path=args.ground_truth,
            review_path=args.review,
        )
        print(json.dumps(report, ensure_ascii=False))
        return 0

    if args.command == "field-validation-report":
        report = run_field_validation(
            args.guardian_report,
            args.repeat_guardian_report,
            args.ground_truth,
            args.review,
            profile=args.profile,
            preregistration_path=args.preregistration,
            roster_path=args.roster,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": args.output,
                    "claim_status": report["claim_status"],
                    "profile": report["profile"],
                    "app_count": report["sample"]["app_count"],
                    "case_count": report["sample"]["case_count"],
                },
                ensure_ascii=False,
            )
        )
        return 0 if report["claim_status"] in {"field_validation_ready", "public_benchmark_ready", "seeded_mutation_regression_ready"} else 3

    if args.command == "data-release-gate":
        report = run_data_release_gate(
            args.guardian_report,
            args.validation_report,
            args.korean_corpus_report,
            args.mcp_intercept_report,
            args.mcp_forwarded_output,
            args.validation_source_guardian_report,
            args.korean_fixture_corpus,
            validation_repeat_guardian_report_path=args.validation_repeat_guardian_report,
            guardian_manifest_path=args.guardian_manifest,
            validation_review_path=args.validation_review,
            validation_ground_truth_path=args.validation_ground_truth,
            validation_preregistration_path=args.validation_preregistration,
            validation_roster_path=args.validation_roster,
            max_validation_false_positive_rate=args.max_validation_fp_rate,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"written": args.output, "passed": report["passed"], "blocking_check_count": report["data_release_gate"]["blocking_check_count"]}, ensure_ascii=False))
        return 0 if report["passed"] else 3

    if args.command == "feedback":
        record = {"type": args.type, "rule": args.rule, "text": _sanitize_feedback_text(args.text, strict=args.type == "fn")}
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(json.dumps({"written": str(output), "type": args.type, "rule": args.rule}, ensure_ascii=False))
        return 0

    if args.command == "feedback-export":
        if not args.reviewed and not _env_flag_enabled("K_GUARD_FEEDBACK_EXPORT_REVIEWED"):
            print(json.dumps({"error": "FEEDBACK_EXPORT_REVIEW_ACK_REQUIRED", "recommendation": "Review sanitized feedback locally, then pass --reviewed or set K_GUARD_FEEDBACK_EXPORT_REVIEWED=1."}, ensure_ascii=False))
            return 2
        summary = _export_feedback(Path(args.input), Path(args.output), max(args.sample_limit, 0))
        print(json.dumps({"written": args.output, "total": summary["total"], "invalid_lines": summary["invalid_lines"]}, ensure_ascii=False))
        return 0

    return 1


def _access_controller_from_args(args: argparse.Namespace) -> AccessPolicyController | None:
    policy_path = str(getattr(args, "access_policy", "") or "").strip()
    app_id = str(getattr(args, "access_app_id", "") or "").strip()
    session_id = str(getattr(args, "access_session_id", "") or "").strip()
    purpose = str(getattr(args, "access_purpose", "") or "").strip()
    audit_path = str(getattr(args, "access_audit_log", "") or "").strip()
    configured_values = (app_id, session_id, purpose, audit_path)
    if not policy_path:
        if any(configured_values):
            raise ValueError("access_policy_required")
        return None
    if not all(configured_values):
        raise ValueError("access_policy_identity_and_audit_required")
    key = _required_secret_env(str(getattr(args, "access_key_env", "") or ""))
    return AccessPolicyController.from_file(
        policy_path,
        key,
        app_id=app_id,
        session_id=session_id,
        purpose=purpose,
        audit_path=audit_path,
        audit_key=key,
    )


def _required_secret_env(name: str) -> str:
    env_name = str(name).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_name):
        raise ValueError("secret_environment_name_invalid")
    value = os.environ.get(env_name)
    if value is None or not value.strip():
        raise ValueError("required_secret_environment_missing")
    return value


def _write_private_text(path: Path, value: str) -> None:
    candidate = path.expanduser().absolute()
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("private_output_already_exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(candidate, flags, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        candidate.chmod(0o600)
    except OSError:
        candidate.unlink(missing_ok=True)
        raise


def _access_policy_template() -> dict[str, object]:
    return {
        "schema": "k_guard_agent_access_policy.v1",
        "issuer": "https://issuer.example.invalid/k-guard",
        "audience": "k-guard-mcp-proxy",
        "max_ttl_seconds": 300,
        "roles": {
            "release-reviewer": {
                "methods": [
                    "initialize",
                    "notifications/initialized",
                    "ping",
                    "tools/list",
                    "tools/call",
                    "resources/list",
                    "resources/read",
                    "prompts/list",
                    "prompts/get",
                    "transport/get",
                    "transport/delete",
                ],
                "tools": [
                    "check_my_app",
                    "continue_review",
                    "start_review_before_ship",
                    "observe_mcp_events",
                ],
                "resources": ["k-guard://public/*"],
                "max_calls": 500,
            }
        },
    }


def _sanitize_feedback_text(value: str, strict: bool = False) -> str:
    redacted = redact_text(value)
    redacted = re.sub(r"\b[가-힣]{2,4}\b", lambda match: redaction_token("PERSON", match.group(0)), redacted)
    if strict:
        return _strict_feedback_mask(redacted)
    return redacted


def _probe_allowed_hosts(base_url: str, allow_external: bool) -> set[str] | None:
    if not allow_external:
        return None
    host = _url_host(base_url)
    allowed = set(ALLOWED_HOSTS)
    if host:
        allowed.add(host)
    return allowed


def _probe_authorization_note(base_url: str, allow_external: bool, note: str) -> str | None:
    if not allow_external:
        return None
    host = _url_host(base_url) or "unknown"
    clean_note = " ".join(str(note).split())[:240]
    if clean_note:
        return f"cli_attestation:{host}:{clean_note}"
    return f"cli_attestation:{host}:operator confirmed owner, partner approval, or bug-bounty scope"


def _url_host(value: str) -> str:
    import urllib.parse

    parsed = urllib.parse.urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").strip("[]").lower()


def _path_ref(path: str | Path) -> dict[str, object]:
    text = str(path)
    return {"hash": evidence_hash(text), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _forwarded_output_ref(path: str | Path, payload: str, event_count: int) -> dict[str, object]:
    ref = _path_ref(path)
    ref.update(
        {
            "content_hash": evidence_hash(payload),
            "byte_count": len(payload.encode("utf-8")),
            "line_count": len([line for line in payload.splitlines() if line.strip()]),
            "event_count": event_count,
        }
    )
    return ref


def _strict_feedback_mask(value: str) -> str:
    parts: list[str] = []
    cursor = 0
    for match in _REDACTION_TOKEN_RE.finditer(value):
        parts.append(_mask_feedback_segment(value[cursor:match.start()]))
        parts.append(match.group(0))
        cursor = match.end()
    parts.append(_mask_feedback_segment(value[cursor:]))
    return "".join(parts)


def _mask_feedback_segment(value: str) -> str:
    value = re.sub(r"\b[A-Za-z0-9][A-Za-z0-9._%+\-:/=@]{3,}\b", lambda match: redaction_token("FEEDBACK_TOKEN", match.group(0)), value)
    return re.sub(r"\b\d{3,}\b", lambda match: redaction_token("FEEDBACK_NUMBER", match.group(0)), value)


def _export_feedback(input_path: Path, output_path: Path, sample_limit: int) -> dict[str, object]:
    by_type: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    samples: list[dict[str, str]] = []
    total = 0
    invalid_lines = 0

    if input_path.exists():
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                raw_record = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(raw_record, dict):
                invalid_lines += 1
                continue

            record_type = _safe_feedback_field(raw_record.get("type"), "unknown")
            rule = _safe_feedback_field(raw_record.get("rule"), "unknown")
            text = _sanitize_feedback_text(_safe_feedback_field(raw_record.get("text"), ""), strict=record_type == "fn")
            by_type[record_type] += 1
            by_rule[rule] += 1
            total += 1
            if len(samples) < sample_limit:
                samples.append({"type": record_type, "rule": rule, "text": text})

    summary = sanitize_any(
        {
            "total": total,
            "invalid_lines": invalid_lines,
            "by_type": dict(sorted(by_type.items())),
            "by_rule": dict(sorted(by_rule.items())),
            "samples": samples,
        }
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def _safe_feedback_field(value: object, default: str) -> str:
    if value is None:
        return default
    return str(value)


def _env_flag_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _guardian_gate(report: dict[str, object], fail_on: str | None) -> dict[str, object] | None:
    return build_guardian_gate(report, fail_on)


def _load_session_headers(path: str, target_url: str) -> SessionMaterial:
    return load_session_material(
        path,
        base_dir=Path.cwd(),
        target_url=target_url,
    )


def _scoreboard_summary(report: dict[str, object]) -> str:
    return json.dumps(
        {
            "passed": report.get("passed"),
            "fixture": report.get("fixture"),
            "positive_count": report.get("positive_count"),
            "negative_count": report.get("negative_count"),
            "measurable_negative_count": report.get("measurable_negative_count"),
            "targeted_absence_case_count": report.get("targeted_absence_case_count"),
            "false_positive_count": report.get("false_positive_count"),
            "recall": report.get("recall"),
            "false_positive_rate": report.get("false_positive_rate"),
            "false_positive_rate_denominator": report.get("false_positive_rate_denominator"),
            "false_positive_rate_denominator_name": report.get("false_positive_rate_denominator_name"),
            "thresholds": report.get("thresholds"),
        },
        ensure_ascii=False,
        indent=2,
    )


if __name__ == "__main__":
    raise SystemExit(main())
