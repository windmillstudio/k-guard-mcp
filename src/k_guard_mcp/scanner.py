from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

from k_guard_mcp.collector import (
    BOUNDED_SECRET_SCAN_MAX_FILE_BYTES,
    FULL_TEXT_SCAN_MAX_FILE_BYTES,
    LOCKFILE_NAMES,
    collect_candidate_files,
    file_inventory_fingerprint,
    is_bounded_large_nonsemantic_asset,
    is_semantic_noise_asset,
    is_unsafe_link,
    read_binary_for_secret_scan,
    read_text,
)
from k_guard_mcp.composite import CompositePiiEngine
from k_guard_mcp.connectors import ReadOnlyConnectorScanner
from k_guard_mcp.cross_plane import CrossPlaneAnalyzer
from k_guard_mcp.detectors import AppRiskDetector, ConfigDetector, DatabasePolicyDetector, McpThreatDetector, PiiDetector, PolyglotRiskDetector, SecretDetector
from k_guard_mcp.dynamic import SafeHttpProbe, _session_headers_indicate_authentication
from k_guard_mcp.flow import FlowAnalyzer
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.governance import KoreanDataGovernanceAnalyzer, OperationalReadinessAnalyzer
from k_guard_mcp.mcp_runtime import McpRuntimeObserver
from k_guard_mcp.models import Finding
from k_guard_mcp.models import ScanResult
from k_guard_mcp.release_policy import (
    DIRECT_RELEASE_BLOCKING_LANE,
    RELEASE_BLOCKING_POLICY,
    SUPPORTING_ARTIFACT_BLOCKING_LANE,
    SUPPORTING_REVIEW_LANE,
    is_release_blocking_finding,
    release_hold_counts,
    release_accounting_lane,
    release_lane,
)
from k_guard_mcp.retention import RetentionDeletionAnalyzer
from k_guard_mcp.rules import RulePackDetector


PRODUCTION_SOURCE_SUFFIXES = {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx", ".py", ".go", ".java", ".kt", ".php", ".rb", ".cs", ".html", ".htm", ".vue", ".svelte", ".sql", ".prisma"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env", ".dockerfile"}
NON_PRODUCTION_PARTS = {"test", "tests", "fixture", "fixtures", "example", "examples", "docs", "benchmarks"}
TEST_PARTS = {"test", "tests", "fixture", "fixtures", "__tests__", "spec", "specs"}
DOCUMENTATION_PARTS = {"doc", "docs", "documentation", "tutorial", "tutorials"}
EXAMPLE_PARTS = {"example", "examples", "demo", "demos", "sample", "samples"}
EXAMPLE_NAME_MARKERS = {"demo", "example", "sample", "template"}
EXAMPLE_CONFIG_NAME_MARKERS = {"config", "configuration", "env", "mcp", "settings"}
BENCHMARK_PARTS = {"benchmark", "benchmarks"}
CONTENT_DATA_PARTS = {"content", "data", "locales", "locale", "i18n", "translations", "translation"}
DEPLOYABLE_ARTIFACT_PARTS = {"build", "dist", "generated", ".next", ".nuxt"}
GENERATED_PARTS = {"coverage"}
THIRD_PARTY_PARTS = {"bower_components", "third-party", "third_party", "vendor", "vendors"}
DOCUMENTATION_NAMES = {"readme", "changelog", "contributing", "security", "code_of_conduct", "license"}
MAX_SCANNED_TEXT_BYTES = FULL_TEXT_SCAN_MAX_FILE_BYTES


class KGuardScanner:
    def __init__(self) -> None:
        self.ids = IdFactory()
        self.secret_detector = SecretDetector(self.ids)
        self.pii_detector = PiiDetector(self.ids)
        self.app_risk_detector = AppRiskDetector(self.ids)
        self.polyglot_risk_detector = PolyglotRiskDetector(self.ids)
        self.config_detector = ConfigDetector(self.ids)
        self.database_policy_detector = DatabasePolicyDetector(self.ids)
        self.mcp_threat_detector = McpThreatDetector(self.ids)
        self.rule_pack_detector = RulePackDetector(self.ids)
        self.composite_engine = CompositePiiEngine(self.ids)
        self.flow_analyzer = FlowAnalyzer(self.ids)
        self.connector_scanner = ReadOnlyConnectorScanner(self.ids)
        self.korean_data_governance = KoreanDataGovernanceAnalyzer(self.ids)
        self.retention_analyzer = RetentionDeletionAnalyzer(self.ids)
        self.cross_plane_analyzer = CrossPlaneAnalyzer(self.ids)
        self.operational_readiness = OperationalReadinessAnalyzer(self.ids)
        self.mcp_runtime_observer = McpRuntimeObserver(self.ids)
        self.http_probe = SafeHttpProbe(self.ids)

    def scan_text(self, text: str, file: str | None = None) -> ScanResult:
        findings = []
        entities = []
        findings.extend(self.secret_detector.scan_text(text, file))
        if is_semantic_noise_asset(file, text):
            _assign_artifact_scopes(findings)
            return ScanResult(findings=findings).finalize()
        findings.extend(self.config_detector.scan_text(text, file))
        findings.extend(self.database_policy_detector.scan_text(text, file))
        pii_findings, pii_entities = self.pii_detector.scan_text(text, file)
        findings.extend(pii_findings)
        entities.extend(pii_entities)
        findings.extend(self.composite_engine.scan_entities(entities, file))
        findings.extend(self.app_risk_detector.scan_text(text, file))
        findings.extend(self.polyglot_risk_detector.scan_text(text, file))
        findings.extend(self.mcp_threat_detector.scan_text(text, file))
        findings.extend(self.rule_pack_detector.scan_text(text, file))
        _assign_artifact_scopes(findings)
        return ScanResult(findings=findings).finalize()

    def scan_workspace(self, path: str | Path, include_flow: bool = True) -> ScanResult:
        result = ScanResult()
        files = collect_candidate_files(path)
        candidate_inventory = file_inventory_fingerprint(path, files)
        reviewed_candidate_count = 0
        decoded_text_file_count = 0
        full_semantic_analysis_candidate_count = 0
        path_classified_secret_only_candidate_count = 0
        binary_secret_scanned_candidate_count = 0
        bounded_large_secret_scanned_candidate_count = 0
        semantic_analysis_limited_candidate_count = 0
        unscanned_candidate_count = 0
        oversized_candidate_count = 0
        unsafe_link_candidate_count = 0
        semantic_noise_file_count = 0
        semantic_noise_byte_count = 0
        scanned_production_source_file_count = 0
        substantive_production_source_file_count = 0
        for file_path in files:
            if is_unsafe_link(file_path):
                unsafe_link_candidate_count += 1
                unscanned_candidate_count += 1
                continue
            try:
                file_size = file_path.stat().st_size
            except OSError:
                file_size = -1
            bounded_large_asset = is_bounded_large_nonsemantic_asset(file_path, file_size)
            oversized = file_size > MAX_SCANNED_TEXT_BYTES
            if oversized and not bounded_large_asset:
                oversized_candidate_count += 1
                unscanned_candidate_count += 1
                continue
            read_limit = BOUNDED_SECRET_SCAN_MAX_FILE_BYTES if bounded_large_asset else MAX_SCANNED_TEXT_BYTES
            try:
                text = read_text(file_path, max_bytes=read_limit)
            except OSError:
                text = None
            if text is None:
                try:
                    binary_text = read_binary_for_secret_scan(file_path, max_bytes=read_limit)
                except OSError:
                    binary_text = None
                if binary_text is None:
                    unscanned_candidate_count += 1
                    continue
                reviewed_candidate_count += 1
                binary_secret_scanned_candidate_count += 1
                semantic_analysis_limited_candidate_count += 1
                semantic_noise_file_count += 1
                semantic_noise_byte_count += max(0, file_size)
                result.findings.extend(self.secret_detector.scan_text(binary_text, str(file_path)))
                continue
            reviewed_candidate_count += 1
            decoded_text_file_count += 1
            if bounded_large_asset:
                bounded_large_secret_scanned_candidate_count += 1
                semantic_analysis_limited_candidate_count += 1
                semantic_noise_file_count += 1
                semantic_noise_byte_count += max(0, file_size)
                result.findings.extend(self.secret_detector.scan_text(text, str(file_path)))
                continue
            semantic_noise = is_semantic_noise_asset(file_path, text)
            semantic_noise_file_count += int(semantic_noise)
            semantic_noise_byte_count += len(text.encode("utf-8", errors="ignore")) if semantic_noise else 0
            if semantic_noise:
                path_classified_secret_only_candidate_count += 1
                semantic_analysis_limited_candidate_count += 1
            else:
                full_semantic_analysis_candidate_count += 1
            scanned_production_source_file_count += int(_is_production_source(file_path))
            substantive_production_source_file_count += int(
                _is_production_source(file_path) and _source_has_substantive_content(text, file_path)
            )
            partial = self.scan_text(text, str(file_path))
            result.findings.extend(partial.findings)
        if include_flow:
            result.flow_map = self.flow_analyzer.build(path)
            result.findings.extend(result.flow_map.findings)
        connector_result = self.connector_scanner.scan_with_evidence(path)
        result.findings.extend(connector_result.findings)
        result.metadata["connector_coverage"] = connector_result.evidence
        result.findings.extend(self.korean_data_governance.scan(path, result.findings))
        result.findings.extend(self.retention_analyzer.scan(path, result.findings))
        result.findings.extend(self.cross_plane_analyzer.scan(result.findings, path))
        result.findings.extend(self.operational_readiness.scan(path))
        _assign_artifact_scopes(result.findings)
        if result.flow_map:
            _assign_artifact_scopes(result.flow_map.findings)
        result.finalize()
        inventory = {
            "supported_file_count": len(files),
            "reviewed_candidate_count": reviewed_candidate_count,
            "scanned_text_file_count": decoded_text_file_count,
            "decoded_text_file_count": decoded_text_file_count,
            "standard_text_pipeline_candidate_count": reviewed_candidate_count - binary_secret_scanned_candidate_count - bounded_large_secret_scanned_candidate_count,
            "full_semantic_analysis_candidate_count": full_semantic_analysis_candidate_count,
            "path_classified_secret_only_candidate_count": path_classified_secret_only_candidate_count,
            "binary_secret_scanned_candidate_count": binary_secret_scanned_candidate_count,
            "bounded_large_secret_scanned_candidate_count": bounded_large_secret_scanned_candidate_count,
            "semantic_analysis_limited_candidate_count": semantic_analysis_limited_candidate_count,
            "unscanned_candidate_count": unscanned_candidate_count,
            "oversized_candidate_count": oversized_candidate_count,
            "unsafe_link_candidate_count": unsafe_link_candidate_count,
            "semantic_noise_file_count": semantic_noise_file_count,
            "semantic_noise_byte_count": semantic_noise_byte_count,
            "semantic_noise_policy": "Candidates completed in a standard, binary, or bounded-large tier receive the declared review. Oversized executable/source candidates and unreadable candidates remain unscanned and fail closed. Secret-only tiers are partial analysis, not full semantic review.",
            "analysis_tier_policy": {
                "full_semantic_text": "decoded source and configuration up to 5 MiB that is not classified as generated/vendor semantic noise",
                "path_classified_secret_only": "decoded generated, vendor, map, stylesheet, lockfile, or large single-line bundle candidate up to 5 MiB",
                "binary_secret_only": "classified binary candidate up to 5 MiB, with a byte-preserving Latin-1 view",
                "bounded_large_secret_only": "non-executable test, fixture, asset, report, snapshot, or license text over 5 MiB and up to 20 MiB",
                "executable_large_file": "unscanned and fail-closed",
                "raw_returned": False,
            },
            "max_scanned_text_bytes": MAX_SCANNED_TEXT_BYTES,
            "candidate_path_set_sha256": candidate_inventory["candidate_path_set_sha256"],
            "candidate_content_set_sha256": candidate_inventory["candidate_content_set_sha256"],
            "content_fingerprint_complete": candidate_inventory["content_fingerprint_complete"],
            "candidate_set_complete": reviewed_candidate_count == len(files) and candidate_inventory["content_fingerprint_complete"] is True,
            "candidate_set_complete_semantics": "all supported candidates completed one declared review tier and were content-bound; this does not mean every candidate received full semantic analysis",
            "full_semantic_candidate_set_complete": (
                reviewed_candidate_count == len(files)
                and semantic_analysis_limited_candidate_count == 0
                and candidate_inventory["content_fingerprint_complete"] is True
            ),
            "production_source_file_count": sum(1 for item in files if _is_production_source(item)),
            "scanned_production_source_file_count": scanned_production_source_file_count,
            "substantive_production_source_file_count": substantive_production_source_file_count,
            "config_file_count": sum(1 for item in files if item.suffix.lower() in CONFIG_SUFFIXES or item.name.lower() in {"dockerfile", "compose.yaml", "compose.yml"}),
            "raw_returned": False,
        }
        result.metadata["review_coverage"] = _workspace_review_coverage(result, include_flow=include_flow, inventory=inventory)
        return result

    def probe_http(
        self,
        base_url: str,
        session_headers: dict[str, str] | None = None,
        active_profile: str = "baseline",
        allowed_hosts: set[str] | None = None,
        authorization_note: str | None = None,
        paths: list[str] | None = None,
        required_paths: list[str] | None = None,
        identity_assertion: dict[str, object] | None = None,
    ) -> ScanResult:
        probe = self.http_probe if allowed_hosts is None else SafeHttpProbe(self.ids, allowed_hosts=allowed_hosts)
        findings, audit_log = probe.probe_with_audit(
            base_url,
            paths=paths,
            session_headers=session_headers,
            active_profile=active_profile,
            identity_assertion=identity_assertion,
        )
        authenticated = _session_headers_indicate_authentication(session_headers)
        if authorization_note:
            findings.append(self._external_authorization_audit_finding(base_url, authorization_note))
        if session_headers and authenticated:
            findings.append(self._session_readonly_audit_finding(session_headers))
        elif session_headers:
            findings.append(self._unrecognized_session_headers_finding(session_headers))
        contract = _dynamic_probe_contract(
            audit_log,
            active_profile,
            authenticated,
            paths,
            required_paths,
            identity_assertion,
        )
        if authenticated and contract.get("identity_assertion_matched") is not True:
            findings.append(self._identity_assertion_unverified_finding(identity_assertion is not None))
        result = ScanResult(findings=findings).finalize()
        result.metadata["dynamic_probe_contract"] = contract
        result.metadata["review_coverage"] = _http_review_coverage(
            result,
            active_profile,
            authenticated,
            paths,
            coverage_complete=contract.get("coverage_complete") is True,
        )
        return result

    def observe_mcp_events(self, text: str, label: str = "mcp-runtime-events") -> ScanResult:
        result = self.mcp_runtime_observer.observe_text(text, label)
        result.findings.extend(self.cross_plane_analyzer.scan(result.findings, label))
        return result.finalize()

    def enforce_mcp_events(self, text: str, label: str = "mcp-runtime-events") -> tuple[ScanResult, list[dict]]:
        result, forwarded_events = self.mcp_runtime_observer.enforce_text(text, label)
        result.findings.extend(self.cross_plane_analyzer.scan(result.findings, label))
        return result.finalize(), forwarded_events

    def observe_mcp_event(self, text: str, session_id: str = "default", label: str = "mcp-runtime-event") -> ScanResult:
        result = self.mcp_runtime_observer.observe_event(text, session_id=session_id, label=label)
        result.findings.extend(self.cross_plane_analyzer.scan(result.findings, label))
        return result.finalize()

    def build_flow_map(self, path: str | Path) -> ScanResult:
        flow = self.flow_analyzer.build(path)
        return ScanResult(findings=flow.findings, flow_map=flow).finalize()

    def _session_readonly_audit_finding(self, session_headers: dict[str, str]) -> Finding:
        header_names = sorted(str(name).lower() for name in session_headers if str(name).strip())
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_AUTH_SESSION_READONLY_AUDIT",
            severity="info",
            confidence="high",
            title="Authenticated read-only probe used user-provided session headers",
            evidence=f"session_header_names={','.join(header_names)} header_count={len(header_names)}",
            why_it_matters="Authenticated read-only probes can inspect screens/APIs that unauthenticated probes cannot, while avoiding mutations.",
            recommendation="Use short-lived least-privilege test sessions and revoke them after audit.",
            audit_depth=4,
            inspected_scope="User-provided headers were attached only to GET requests; header values were not stored.",
            not_inspected="The scanner did not submit forms, mutate data, or verify session ownership beyond operator-provided input.",
        )

    def _unrecognized_session_headers_finding(self, session_headers: dict[str, str]) -> Finding:
        header_names = sorted(str(name).lower() for name in session_headers if str(name).strip())
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_AUTH_SESSION_HEADER_UNRECOGNIZED",
            severity="high",
            confidence="high",
            title="Session file does not contain a recognized authentication header",
            evidence=f"header_name_refs={','.join(evidence_hash(name) for name in header_names)} header_count={len(header_names)} scheme={evidence_hash_scheme()} raw_returned=false",
            why_it_matters="An arbitrary request header must not satisfy authenticated coverage or suppress unauthenticated exposure findings.",
            recommendation="Provide a least-privilege test Authorization, Cookie, token, session, API-key, JWT, or assertion header and rerun both unauthenticated and authenticated probes.",
            audit_depth=4,
            inspected_scope="K-Guard classified only non-empty authentication-, cookie-, token-, session-, API-key-, JWT-, or assertion-bearing request headers as session evidence.",
            not_inspected="K-Guard does not validate the credential owner or prove that the target accepted the credential.",
        )

    def _identity_assertion_unverified_finding(self, assertion_supplied: bool) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_AUTH_IDENTITY_UNVERIFIED",
            severity="high",
            confidence="high",
            title="Authenticated identity assertion was not verified",
            evidence=(
                "detector_subtype=auth_identity_assertion_unverified "
                f"assertion_supplied={str(assertion_supplied).lower()} assertion_matched=false raw_returned=false"
            ),
            why_it_matters="A Cookie or Authorization header alone does not prove that the target accepted the intended test user or role.",
            recommendation="Bind the short-lived session to the exact origin and provide a stable identity endpoint status and response SHA-256.",
            audit_depth=4,
            inspected_scope="The asserted GET response was compared by path, status, and body digest without returning body content.",
            not_inspected="Object ownership and role boundaries require separately asserted principals and authorized resource tests.",
        )

    def _external_authorization_audit_finding(self, base_url: str, authorization_note: str) -> Finding:
        note_present = bool(str(authorization_note or "").strip())
        return Finding(
            id=self.ids.next(),
            source="dynamic",
            rule_id="DYN_EXTERNAL_TARGET_AUTHORIZATION_AUDIT",
            severity="info",
            confidence="high",
            title="External target probe authorization was recorded",
            evidence=(
                f"target_ref={evidence_hash(base_url)} authorization_note_present={str(note_present).lower()} "
                f"authorization_note_ref={evidence_hash(str(authorization_note or ''))} scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            why_it_matters="Authorized external probes are useful for real deployed apps, but the authorization basis must travel with the result.",
            recommendation="Keep proof of ownership, partner approval, or bug-bounty scope with the audit report.",
            audit_depth=4,
            inspected_scope="The dynamic probe was allowed to send fixed read-only GET/OPTIONS checks to this external origin.",
            not_inspected="This does not grant permission for login attempts, password guessing, mutation, exploit payloads, recursive crawling, or scanning other origins.",
        )


def _workspace_review_coverage(
    result: ScanResult,
    *,
    include_flow: bool,
    inventory: dict,
) -> dict:
    rule_ids = {finding.rule_id for finding in result.findings}
    artifact_counts = Counter(finding.artifact_scope or "workspace_evidence" for finding in result.findings)
    high_critical_artifact_counts = Counter(
        finding.artifact_scope or "workspace_evidence"
        for finding in result.findings
        if finding.severity in {"critical", "high"}
    )
    return {
        "capability": "korean_senior_pre_release_v1",
        "source_kind": "workspace",
        "domains": {
            "site_security": {
                "status": "completed_static",
                "checks": ["web_input_sinks", "session_and_cookie_patterns", "deployment_config", "client_exposure"],
                "finding_rule_count": _rule_count(rule_ids, ("WEB_", "AUTH_", "CONFIG_", "JS_TS_")),
            },
            "api_exposure": {
                "status": "completed_static",
                "checks": ["route_auth_boundary", "idor_bola", "mass_assignment", "ssrf", "injection", "response_flow"],
                "finding_rule_count": _rule_count(rule_ids, ("API_", "AST_TAINT_", "JS_TS_", "FLOW_")),
            },
            "data_management": {
                "status": (
                    "completed_static_and_local_storage"
                    if result.metadata.get("connector_coverage", {}).get("complete") is True
                    else "incomplete_fail_closed"
                ),
                "checks": ["korean_pii", "unique_and_sensitive_fields", "local_storage", "postgres_policy_migrations", "retention", "erasure", "external_processor_flow"],
                "finding_rule_count": _rule_count(rule_ids, ("PII_", "KR_", "CONNECTOR_", "DB_POLICY_", "RETENTION_", "CROSS_PLANE_")),
            },
            "operational_risk": {
                "status": "completed_static",
                "checks": ["dependency_lock", "ci_gate", "auth_tests", "rate_limit_evidence", "mcp_configuration"],
                "finding_rule_count": _rule_count(rule_ids, ("RELEASE_", "MCP_", "RULE_", "CONFIG_")),
            },
        },
        "flow_analysis_executed": include_flow and result.flow_map is not None,
        "detector_execution_contract": {
            "coverage_reducing_performance_shortcuts": False,
            "rule_pack_matching": "Built-in regular-expression results may be cached by exact rule id and complete source line; no mandatory-hint prefilter narrows the match set.",
            "polyglot_js_ts_matching": "The bounded JS/TS pass executes without a file-level sink prefilter.",
            "mcp_ascii_normalization": "The fast path applies only when ASCII normalization is an identity operation; encoded and Unicode candidates continue through bounded normalization.",
            "residual_risk": "The detectors remain bounded lexical and heuristic analyses; this execution contract does not add new semantic coverage beyond their declared rule families.",
            "raw_returned": False,
        },
        "inventory": inventory,
        "connector_coverage": result.metadata.get("connector_coverage", {}),
        "untrusted_content_boundary": {
            "repository_content_role": "data_only",
            "analyzer_execution": "deterministic_local",
            "raw_source_returned": False,
            "repository_text_used_as_agent_instruction": False,
            "client_independent_file_reads_out_of_scope": True,
        },
        "finding_artifact_scope_counts": dict(sorted(artifact_counts.items())),
        "high_critical_artifact_scope_counts": dict(sorted(high_critical_artifact_counts.items())),
        "review_triage": build_review_triage(result.findings),
        "raw_returned": False,
        "limitations": [
            "Local SQLite uses an AST/RBAC/EXPLAIN/read-only gate and PostgreSQL/Supabase migrations receive bounded static policy review; deployed database state, cloud IAM, load tests, and human business intent still require external evidence.",
            "JS/TS inter-procedural and framework understanding remains bounded and heuristic.",
            "An MCP client or external reviewer that independently reads repository files must enforce its own prompt-isolation boundary; K-Guard does not forward source text as instructions.",
        ],
    }


def _is_production_source(path: Path) -> bool:
    if path.suffix.lower() not in PRODUCTION_SOURCE_SUFFIXES:
        return False
    try:
        if is_bounded_large_nonsemantic_asset(path, path.stat().st_size):
            return False
    except OSError:
        pass
    if is_semantic_noise_asset(path):
        return False
    if _is_test_source_path(path) or any(part.lower() in NON_PRODUCTION_PARTS for part in path.parts):
        return False
    stem = path.stem.lower()
    return not (stem.startswith("test_") or stem.endswith("_test") or stem.endswith(".test") or stem.endswith(".spec"))


def classify_artifact_scope(path: str | Path | None) -> str:
    if not path:
        return "workspace_evidence"
    candidate = Path(str(path).replace("\\", "/"))
    parts = {part.lower() for part in candidate.parts}
    name = candidate.name.lower()
    stem = candidate.stem.lower()
    try:
        if is_bounded_large_nonsemantic_asset(candidate, candidate.stat().st_size):
            return "repository_asset"
    except OSError:
        pass
    if _is_test_source_path(candidate) or parts & TEST_PARTS or stem.startswith("test_") or any(
        marker in name for marker in (".test.", ".spec.", "_test.")
    ):
        return "test_fixture"
    if parts & BENCHMARK_PARTS:
        return "benchmark"
    if "resources" in parts and parts & {"lesson", "lessons"}:
        return "documentation"
    if parts & DOCUMENTATION_PARTS or stem in DOCUMENTATION_NAMES or name.startswith("readme."):
        return "documentation"
    if parts & EXAMPLE_PARTS or _is_example_config_name(name):
        return "example"
    if name in LOCKFILE_NAMES:
        return "repository_asset"
    if parts & DEPLOYABLE_ARTIFACT_PARTS:
        return "deployable_artifact"
    if parts & GENERATED_PARTS:
        return "generated"
    if parts & THIRD_PARTY_PARTS or is_semantic_noise_asset(candidate):
        return "third_party"
    if parts & CONTENT_DATA_PARTS:
        return "content_data"
    if candidate.suffix.lower() in CONFIG_SUFFIXES or name in {"dockerfile", "compose.yaml", "compose.yml"}:
        return "configuration"
    if candidate.suffix.lower() in PRODUCTION_SOURCE_SUFFIXES:
        return "runtime_source"
    return "repository_asset"


def _is_example_config_name(name: str) -> bool:
    tokens = [token for token in re.split(r"[^a-z0-9]+", name.casefold()) if token]
    return any(
        left in EXAMPLE_NAME_MARKERS and right in EXAMPLE_CONFIG_NAME_MARKERS
        or left in EXAMPLE_CONFIG_NAME_MARKERS and right in EXAMPLE_NAME_MARKERS
        for left, right in zip(tokens, tokens[1:])
    )


def _is_test_source_path(path: Path) -> bool:
    parts = tuple(part.lower() for part in path.parts)
    if any(part in TEST_PARTS for part in parts):
        return True
    if any(parts[index] == "src" and parts[index + 1] in {"it", "test"} for index in range(len(parts) - 1)):
        return True
    suffix = path.suffix.lower()
    stem = path.stem
    return suffix in {".java", ".kt", ".kts"} and (
        stem.startswith("Test") or stem.endswith(("Test", "Tests", "TestCase"))
    )


def _assign_artifact_scopes(findings: list[Finding]) -> None:
    for finding in findings:
        if not finding.artifact_scope:
            finding.artifact_scope = classify_artifact_scope(finding.file)


def build_review_triage(findings: list[Finding], *, limit: int = 50) -> dict:
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        scope = finding.artifact_scope or "workspace_evidence"
        groups.setdefault((finding.rule_id, finding.severity, scope), []).append(finding)
    ordered = sorted(
        groups.items(),
        key=lambda item: (
            0 if any(is_release_blocking_finding(finding, "high") for finding in item[1]) else 1,
            _severity_order(item[0][1]),
            -len(item[1]),
            item[0][0],
            item[0][2],
        ),
    )
    rows = []
    for (rule_id, severity, scope), group in ordered[:limit]:
        rows.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "artifact_scope": scope,
                "priority_lane": release_lane(group[0], "high"),
                "finding_count": len(group),
                "affected_file_count": len({finding.file for finding in group if finding.file}),
                "location_refs": sorted(
                    {
                        evidence_hash(f"{finding.file or ''}:{finding.line_start or 0}")
                        for finding in group
                    }
                )[:5],
                "raw_returned": False,
            }
        )
    high_critical = [finding for finding in findings if finding.severity in {"critical", "high"}]
    accounting_counts = Counter(release_accounting_lane(finding, "high") for finding in high_critical)
    hold_counts = release_hold_counts(high_critical, "high")
    blocking = [finding for finding in high_critical if is_release_blocking_finding(finding, "high")]
    blocking_group_count = len(
        {
            (finding.rule_id, finding.artifact_scope or "workspace_evidence")
            for finding in blocking
        }
    )
    return {
        "finding_count": len(findings),
        "action_group_count": len(groups),
        "blocking_finding_count": len(blocking),
        "blocking_action_group_count": blocking_group_count,
        "automatic_release_blocking_count": hold_counts["automatic_release_blocking_count"],
        "manual_review_hold_count": hold_counts["manual_review_hold_count"],
        "policy_integrity_hold_count": hold_counts["policy_integrity_hold_count"],
        "direct_release_blocking_count": accounting_counts[DIRECT_RELEASE_BLOCKING_LANE],
        "supporting_artifact_blocking_count": accounting_counts[SUPPORTING_ARTIFACT_BLOCKING_LANE],
        "supporting_review_high_critical_count": accounting_counts[SUPPORTING_REVIEW_LANE],
        "groups": rows,
        "groups_truncated": len(groups) > limit,
        "all_findings_remain_in_report": True,
        "gate_still_evaluates_all_findings": False,
        "gate_uses_release_blocking_policy": True,
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
        "raw_returned": False,
    }


def _severity_order(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def _source_has_substantive_content(text: str, path: Path) -> bool:
    if not text.strip():
        return False
    if path.suffix.lower() == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return False
        return any(_python_statement_is_substantive(node) for node in tree.body)
    uncommented = re.sub(r"/\*.*?\*/|<!--.*?-->", "", text, flags=re.DOTALL)
    code_lines = [
        line.strip()
        for line in uncommented.splitlines()
        if line.strip() and not line.lstrip().startswith(("//", "#", "*"))
    ]
    significant = "".join(code_lines)
    return len(re.findall(r"[A-Za-z0-9가-힣]", significant)) >= 4


def _python_statement_is_substantive(node: ast.stmt) -> bool:
    if isinstance(node, (ast.Pass, ast.Import, ast.ImportFrom)):
        return False
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and (isinstance(node.value.value, str) or node.value.value is Ellipsis):
        return False
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return any(_python_statement_is_substantive(child) for child in node.body)
    return True


def _dynamic_probe_contract(
    audit_log: list,
    active_profile: str,
    authenticated: bool,
    paths: list[str] | None,
    required_paths: list[str] | None,
    identity_assertion: dict[str, object] | None = None,
) -> dict:
    request_logs = [item for item in audit_log if getattr(item, "check", "") == "HTTP 요청"]
    observed_refs = {
        str(getattr(item, "probe_path_ref", ""))
        for item in request_logs
        if str(getattr(item, "probe_path_ref", ""))
    }
    required_paths_normalized = {
        path if str(path).startswith("/") else "/" + str(path)
        for path in (required_paths or [])
    }
    required_refs = {evidence_hash(path) for path in required_paths_normalized}
    reached_refs = {
        str(getattr(item, "probe_path_ref", ""))
        for item in request_logs
        if getattr(item, "method", "") == "GET"
        and str(getattr(item, "probe_path_ref", ""))
        and getattr(item, "status", None) is not None
        and (200 <= int(getattr(item, "status")) < 300 or int(getattr(item, "status")) in {401, 403})
    }
    required_reached_refs = required_refs & reached_refs
    observations = []
    for item in request_logs:
        path = str(getattr(item, "probe_path", ""))
        observations.append(
            {
                "path_ref": str(getattr(item, "probe_path_ref", "")) or evidence_hash(path),
                "method": str(getattr(item, "method", "")),
                "status": getattr(item, "status", None),
                "response_hash": str(getattr(item, "response_hash", "")),
                "response_class": str(getattr(item, "response_class", "unknown")),
                "auth_wall": bool(getattr(item, "auth_wall", False)),
                "private_data_signal": bool(getattr(item, "private_data_signal", False)),
                "authenticated": bool(getattr(item, "authenticated", False)),
                "path_source": str(getattr(item, "path_source", "configured")),
                "identity_assertion_match": bool(getattr(item, "identity_assertion_match", False)),
                "raw_returned": False,
            }
        )
    observations.sort(key=lambda item: (item["path_ref"], item["method"], str(item["status"])))
    error_request_count = sum(1 for item in request_logs if getattr(item, "result", "") == "error")
    control_error_count = sum(
        1
        for item in audit_log
        if getattr(item, "result", "") == "error" and getattr(item, "check", "") != "HTTP 요청"
    )
    discovered_refs = sorted(
        {
            str(getattr(item, "probe_path_ref", ""))
            for item in audit_log
            if str(getattr(item, "path_source", "")).startswith("openapi_discovered")
            and str(getattr(item, "probe_path_ref", ""))
        }
    )
    identity_assertion_matched = any(bool(item.get("identity_assertion_match")) for item in observations)
    identity_coverage_complete = not authenticated or (bool(identity_assertion) and identity_assertion_matched)
    return {
        "active_profile": active_profile,
        "authenticated": authenticated,
        "requested_custom_path_count": len(paths or []),
        "observed_path_count": len(observed_refs),
        "request_count": len(request_logs),
        "error_request_count": error_request_count,
        "control_error_count": control_error_count,
        "coverage_complete": bool(request_logs) and error_request_count == 0 and control_error_count == 0 and len(required_reached_refs) == len(required_refs) and identity_coverage_complete,
        "methods": sorted({str(getattr(item, "method", "")) for item in request_logs if getattr(item, "method", "")}),
        "successful_get_path_count": len(reached_refs),
        "required_path_count": len(required_refs),
        "required_path_reached_count": len(required_reached_refs),
        "required_path_refs": sorted(required_refs),
        "required_path_reached_refs": sorted(required_reached_refs),
        "openapi_discovered_path_count": len(discovered_refs),
        "openapi_discovered_path_refs": discovered_refs,
        "openapi_discovered_paths_executed": False,
        "identity_assertion_supplied": bool(identity_assertion),
        "identity_assertion_matched": identity_assertion_matched,
        "response_observations": observations,
        "raw_returned": False,
    }


def _http_review_coverage(
    result: ScanResult,
    active_profile: str,
    authenticated: bool,
    paths: list[str] | None,
    *,
    coverage_complete: bool,
) -> dict:
    rule_ids = {finding.rule_id for finding in result.findings}
    dynamic_status = "completed_dynamic_deep" if active_profile == "deep" else "completed_dynamic_baseline"
    if not coverage_complete:
        dynamic_status = "incomplete_fail_closed"
    return {
        "capability": "korean_senior_pre_release_v1",
        "source_kind": "http",
        "domains": {
            "site_security": {
                "status": dynamic_status,
                "checks": ["security_headers", "cookie_flags", "cors", "debug", "source_map", "sensitive_files"],
                "finding_rule_count": _rule_count(rule_ids, ("DYN_",)),
            },
            "api_exposure": {
                "status": "completed_dynamic_read_only" if coverage_complete else "incomplete_fail_closed",
                "checks": ["unauthenticated_json", "declared_paths", "openapi", "admin_boundary", "sensitive_response"],
                "custom_path_count": len(paths or []),
                "authenticated_session_used": authenticated,
                "finding_rule_count": _rule_count(rule_ids, ("DYN_UNAUTH_", "DYN_RESPONSE_", "DYN_OPENAPI_")),
            },
            "data_management": {
                "status": "response_surface_only",
                "checks": ["response_pii", "response_secret", "sensitive_cache_policy"],
                "finding_rule_count": _rule_count(rule_ids, ("DYN_RESPONSE_",)),
            },
            "operational_risk": {
                "status": "runtime_surface_only",
                "checks": ["debug_runtime", "backup_exposure", "redirect_boundary"],
                "finding_rule_count": _rule_count(rule_ids, ("DYN_",)),
            },
        },
        "raw_returned": False,
        "limitations": [
            "GET/OPTIONS only; no mutation, fuzzing, login attempt, exploit payload, or recursive crawl.",
            "Authenticated coverage exists only when the operator supplies a read-only session file.",
        ],
    }


def _rule_count(rule_ids: set[str], prefixes: tuple[str, ...]) -> int:
    return sum(1 for rule_id in rule_ids if rule_id.startswith(prefixes))
