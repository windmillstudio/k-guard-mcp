from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from k_guard_mcp.collector import collect_files, read_text
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding
from k_guard_mcp.sensitive_vocabulary import GOVERNANCE_SENSITIVE_FIELDS as SENSITIVE_FIELDS


UNIQUE_IDENTIFIER_FIELDS = (
    "rrn",
    "resident_registration_number",
    "resident_no",
    "jumin",
    "jumin_no",
    "foreigner_registration_number",
    "foreigner_no",
    "passport_number",
    "passport_no",
    "driver_license_number",
    "driver_license_no",
    "주민등록번호",
    "외국인등록번호",
    "여권번호",
    "운전면허번호",
)

HIGH_IMPACT_SERVICE_FIELDS = (
    "personal_customs_code",
    "personal_customs_clearance_code",
    "connecting_info",
    "duplication_info",
    "health_insurance_id",
    "health_insurance_number",
    "개인통관고유부호",
    "연계정보",
    "중복가입확인정보",
    "건강보험증번호",
)

AMBIGUOUS_LINKABLE_FIELDS = ("ci", "di")
KOREAN_IDENTITY_CONTEXT = re.compile(
    r"(identity[_ -]?(?:verification|proof)|identityprovider|본인\s*인증|실명\s*인증|연계정보|중복가입|\bnice[A-Za-z0-9_.-]*(?:identity|verify|auth)|\bkcb[A-Za-z0-9_.-]*(?:identity|verify|auth)|\bpass[_ -]?auth\b)",
    re.IGNORECASE,
)

ENCRYPTION_MARKER = re.compile(
    r"(encrypt|decrypt|envelope[_ -]?encryption|field[_ -]?encryption|tokeni[sz]e|vault|kms|pgcrypto|fernet|aes[_ -]?(?:gcm|256)|crypto\.subtle|암호화|복호화|토큰화)",
    re.IGNORECASE,
)
ACCESS_CONTROL_MARKER = re.compile(
    r"(authori[sz]e|permission|owner[_ -]?id|tenant[_ -]?id|row[_ -]?level[_ -]?security|\brls\b|access[_ -]?control|scope[_ -]?check|권한\s*확인|접근\s*통제|소유자\s*확인)",
    re.IGNORECASE,
)
ACCESS_AUDIT_MARKER = re.compile(
    r"(audit[_ -]?log|access[_ -]?log|security[_ -]?log|audit[_ -]?trail|접근\s*기록|접속\s*기록|감사\s*로그)",
    re.IGNORECASE,
)
TRANSFER_GOVERNANCE_MARKER = re.compile(
    r"(third[_ -]?party|processor|subprocessor|cross[_ -]?border|overseas[_ -]?transfer|privacy[_ -]?policy|제3자\s*제공|처리\s*위탁|수탁|국외\s*(?:이전|전송))",
    re.IGNORECASE,
)
API_SURFACE_MARKER = re.compile(
    r"(export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)|(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|@(?:app|router)\.(?:get|post|put|patch|delete)|@(?:Get|Post|Put|Patch|Delete)Mapping)",
    re.IGNORECASE,
)
RATE_LIMIT_MARKER = re.compile(r"(rate[_ -]?limit|ratelimit|slowdown|throttl|limiter|요청\s*제한)", re.IGNORECASE)
AUTH_SURFACE_MARKER = re.compile(r"(login|sign[_ -]?in|authenticate|password|oauth|session|로그인|인증)", re.IGNORECASE)
TEST_FILE_MARKER = re.compile(r"(?:^|[_.-])(?:test|spec)(?:[_.-]|$)", re.IGNORECASE)
EXTERNAL_FLOW_RULE = re.compile(r"(?:TO_EXTERNAL|EXTERNAL_HTTP|EXTERNAL_SINK|EXFIL)", re.IGNORECASE)
PRIVACY_RULE = re.compile(r"(?:^PII_|^KR_COMBO_|DYN_RESPONSE_PII|CONNECTOR_.*PII|SENSITIVE)", re.IGNORECASE)

SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".kt", ".php", ".rb", ".cs", ".sql", ".prisma"}
CONTROL_EVIDENCE_SUFFIXES = SOURCE_SUFFIXES | {".json", ".yaml", ".yml", ".toml", ".ini", ".conf"}
NON_PRODUCTION_PARTS = {"test", "tests", "fixture", "fixtures", "example", "examples", "docs", "benchmarks"}
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}
GOVERNED_FIELD_HINT = re.compile(
    "|".join(
        re.escape(name).replace("_", r"[_\-\s]*")
        for name in (*UNIQUE_IDENTIFIER_FIELDS, *HIGH_IMPACT_SERVICE_FIELDS, *SENSITIVE_FIELDS)
    ),
    re.IGNORECASE,
)
AMBIGUOUS_FIELD_HINT = re.compile(r"\b(?:ci|di)\b", re.IGNORECASE)
GOVERNANCE_PREFILTER_MARKERS = tuple(
    sorted(
        {
            *(name.lower().split("_", 1)[0] for name in (*UNIQUE_IDENTIFIER_FIELDS, *HIGH_IMPACT_SERVICE_FIELDS, *SENSITIVE_FIELDS)),
            "ci",
            "di",
            "encrypt",
            "decrypt",
            "envelope",
            "field",
            "tokeni",
            "vault",
            "kms",
            "pgcrypto",
            "fernet",
            "aes",
            "crypto.subtle",
            "암호화",
            "복호화",
            "토큰화",
            "authori",
            "permission",
            "owner",
            "tenant",
            "row",
            "rls",
            "access",
            "scope",
            "권한",
            "접근",
            "소유자",
            "audit",
            "security",
            "접속",
            "감사",
            "third",
            "processor",
            "cross",
            "overseas",
            "privacy",
            "제3자",
            "처리",
            "수탁",
            "국외",
        }
    )
)


@dataclass(frozen=True)
class FieldControlRef:
    path: Path
    line_no: int
    name: str
    encryption: bool
    access_control: bool
    access_audit: bool


class KoreanDataGovernanceAnalyzer:
    """Checks technical evidence around Korean unique/sensitive data handling."""

    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan(self, root: str | Path, findings: list[Finding]) -> list[Finding]:
        files = collect_files(root)
        declarations: list[tuple[Path, int, str, str]] = []
        control_lines: list[tuple[Path, int, str]] = []
        transfer_governance_present = False

        for path in files:
            text = read_text(path)
            if not text or not _governance_text_relevant(text):
                continue
            clean_lines = _code_lines_without_comments(text)
            if _control_evidence_file(path):
                control_lines.extend((path, line_no, line) for line_no, line in enumerate(clean_lines, start=1) if line.strip())
                transfer_governance_present = transfer_governance_present or any(TRANSFER_GOVERNANCE_MARKER.search(line) for line in clean_lines)
            if not _production_source(path):
                continue
            for line_no, line in enumerate(clean_lines, start=1):
                candidates = _declared_field_candidates(line)
                unique_name = _declared_field_from_candidates(candidates, UNIQUE_IDENTIFIER_FIELDS)
                if unique_name:
                    declarations.append((path, line_no, unique_name, "unique_identifier"))
                service_name = _declared_field_from_candidates(candidates, HIGH_IMPACT_SERVICE_FIELDS)
                if service_name:
                    declarations.append((path, line_no, service_name, "high_impact_service_identifier"))
                ambiguous_name = _declared_field_from_candidates(candidates, AMBIGUOUS_LINKABLE_FIELDS)
                if ambiguous_name:
                    context_window = "\n".join(
                        _code_without_string_literals(context_line)
                        for context_line in clean_lines[max(0, line_no - 5): min(len(clean_lines), line_no + 2)]
                    )
                    if KOREAN_IDENTITY_CONTEXT.search(context_window):
                        declarations.append((path, line_no, ambiguous_name, "high_impact_service_identifier"))
                sensitive_name = _declared_field_from_candidates(candidates, SENSITIVE_FIELDS)
                if sensitive_name:
                    declarations.append((path, line_no, sensitive_name, "sensitive_information"))

        classified: dict[str, list[FieldControlRef]] = {
            "unique_identifier": [],
            "high_impact_service_identifier": [],
            "sensitive_information": [],
        }
        for path, line_no, name, category in declarations:
            encryption, access_control, access_audit = _field_control_state(path, line_no, name, control_lines)
            classified[category].append(FieldControlRef(path, line_no, name, encryption, access_control, access_audit))

        unique_refs = classified["unique_identifier"]
        service_refs = classified["high_impact_service_identifier"]
        sensitive_refs = classified["sensitive_information"]

        results: list[Finding] = []
        unique_gaps = [ref for ref in unique_refs if not ref.encryption or not ref.access_control]
        if unique_gaps:
            results.append(
                self._control_gap_finding(
                    root,
                    "KR_DATA_UNIQUE_IDENTIFIER_CONTROL_GAP",
                    "Korean unique-identifier fields lack visible protection evidence",
                    "unique_identifier",
                    unique_gaps,
                    "Resident/foreigner registration numbers and similar identifiers require especially narrow handling because misuse has high identity-impact in Korea.",
                    "Encrypt or tokenize the field, enforce server-side purpose/role/owner checks, minimize collection, and document the lawful handling basis outside this report.",
                )
            )
        service_gaps = [ref for ref in service_refs if not ref.encryption or not ref.access_control]
        if service_gaps:
            results.append(
                self._control_gap_finding(
                    root,
                    "KR_DATA_LINKABLE_IDENTIFIER_CONTROL_GAP",
                    "Linkable Korean service identifiers lack field-correlated protection evidence",
                    "high_impact_service_identifier",
                    service_gaps,
                    "CI, DI, customs, and insurance identifiers can link or expose a person across high-impact service workflows even when they are not classified here as statutory unique identifiers.",
                    "Encrypt or tokenize the field, bind access to a documented service purpose, and add field-specific authorization tests.",
                )
            )
        sensitive_gaps = [ref for ref in sensitive_refs if not ref.encryption or not ref.access_control]
        if sensitive_gaps:
            results.append(
                self._control_gap_finding(
                    root,
                    "KR_DATA_SENSITIVE_INFORMATION_CONTROL_GAP",
                    "Sensitive-information fields lack visible protection evidence",
                    "sensitive_information",
                    sensitive_gaps,
                    "Health, disability, biometric, belief, criminal-history, and similar fields have elevated impact and need explicit technical boundaries.",
                    "Encrypt or tokenize sensitive fields, enforce least-privilege access, separate them from general profile data, and add authorization tests.",
                )
            )
        high_impact_refs = unique_refs + service_refs + sensitive_refs
        audit_gaps = [ref for ref in high_impact_refs if not ref.access_audit]
        if audit_gaps:
            first = audit_gaps[0]
            results.append(
                Finding(
                    id=self.ids.next(),
                    source="korean-data-governance",
                    rule_id="KR_DATA_ACCESS_LOG_EVIDENCE_MISSING",
                    severity="medium",
                    confidence="medium",
                    title="No access-audit evidence was found for high-impact personal data",
                    file=str(first.path),
                    line_start=first.line_no,
                    line_end=first.line_no,
                    evidence=(
                        f"detector_subtype=high_impact_access_audit_gap field_count={len(audit_gaps)} "
                        f"first_field_ref={evidence_hash(str(first.path) + ':' + str(first.line_no))} scheme={evidence_hash_scheme()} raw_returned=false"
                    ),
                    why_it_matters="A senior Korean data review should be able to determine who accessed high-impact identifiers or sensitive records and when.",
                    recommendation="Add tamper-resistant access/audit events with actor, purpose, object class, result, and retention controls while excluding raw sensitive values.",
                    audit_depth=4,
                    inspected_scope="Production declarations were checked for uncommented, field-correlated access-audit markers in the same source artifact.",
                    not_inspected="This check does not inspect deployed SIEM retention, database audit extensions, or legal compliance evidence outside the workspace.",
                )
            )

        has_privacy = bool(unique_refs or service_refs or sensitive_refs or any(PRIVACY_RULE.search(item.rule_id) for item in findings))
        has_external_flow = any(EXTERNAL_FLOW_RULE.search(item.rule_id) for item in findings)
        if has_privacy and has_external_flow and not transfer_governance_present:
            results.append(
                Finding(
                    id=self.ids.next(),
                    source="korean-data-governance",
                    rule_id="KR_DATA_EXTERNAL_PROCESSOR_REVIEW_REQUIRED",
                    severity="medium",
                    confidence="medium",
                    title="Personal-data flow to an external service lacks visible transfer/processor review evidence",
                    file=str(Path(root)),
                    evidence=(
                        "detector_subtype=personal_data_external_processor_review "
                        f"privacy_signal=true external_flow=true scheme={evidence_hash_scheme()} raw_returned=false"
                    ),
                    why_it_matters="External APIs, analytics, AI, and MCP services may become processors or overseas transfer points depending on the actual provider and deployment region.",
                    recommendation="Inventory the recipient, fields, purpose, region, retention, subprocessors, and user notice/consent basis; minimize or redact data before transfer.",
                    audit_depth=4,
                    inspected_scope="K-Guard correlated workspace privacy findings with static external-sink findings and searched local text for transfer/processor governance markers.",
                    not_inspected="K-Guard does not determine vendor region, contract terms, lawful basis, or whether the transfer is legally compliant.",
                )
            )
        return results

    def _control_gap_finding(
        self,
        root: str | Path,
        rule_id: str,
        title: str,
        subtype: str,
        refs: list[FieldControlRef],
        why: str,
        recommendation: str,
    ) -> Finding:
        first = refs[0]
        encryption_complete = all(ref.encryption for ref in refs)
        access_control_complete = all(ref.access_control for ref in refs)
        return Finding(
            id=self.ids.next(),
            source="korean-data-governance",
            rule_id=rule_id,
            severity="high",
            confidence="medium",
            title=title,
            file=str(first.path),
            line_start=first.line_no,
            line_end=first.line_no,
            evidence=(
                f"detector_subtype={subtype}_control_gap field_count={len(refs)} "
                f"field_name_ref={evidence_hash(first.name)} first_field_ref={evidence_hash(str(first.path) + ':' + str(first.line_no))} "
                f"field_correlated_encryption_complete={str(encryption_complete).lower()} "
                f"field_correlated_access_control_complete={str(access_control_complete).lower()} "
                f"scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            why_it_matters=why,
            recommendation=recommendation,
            audit_depth=4,
            inspected_scope="Each production field declaration was correlated with uncommented encryption/tokenization and access-control code that names the same field in the same source artifact.",
            not_inspected="Static field correlation is not proof of runtime enforcement; deployed database policy, key custody, legal basis, and business necessity require separate verification.",
        )


class OperationalReadinessAnalyzer:
    """Finds release-process gaps that a senior pre-release review should surface."""

    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan(self, root: str | Path) -> list[Finding]:
        base = Path(root).resolve()
        files = collect_files(base)
        names = {path.name.lower() for path in files}
        package_json_present = "package.json" in names
        lockfile_present = bool(names & LOCKFILE_NAMES)
        api_surface_count = 0
        rate_limit_present = False
        auth_surface_present = False
        test_file_count = 0
        ci_present = any(".github" in {part.lower() for part in path.parts} and path.suffix.lower() in {".yml", ".yaml"} for path in files)

        for path in files:
            if TEST_FILE_MARKER.search(path.stem) or any(part.lower() in {"test", "tests"} for part in path.parts):
                test_file_count += 1
            if not _production_source(path):
                continue
            text = read_text(path)
            if not text:
                continue
            uncommented = "\n".join(_code_lines_without_comments(text))
            api_surface_count += len(API_SURFACE_MARKER.findall(uncommented))
            rate_limit_present = rate_limit_present or bool(RATE_LIMIT_MARKER.search(uncommented))
            auth_surface_present = auth_surface_present or bool(AUTH_SURFACE_MARKER.search(uncommented))

        results: list[Finding] = []
        if package_json_present and not lockfile_present:
            results.append(
                self._finding(
                    base,
                    "RELEASE_DEPENDENCY_LOCK_MISSING",
                    "medium",
                    "high",
                    "JavaScript dependencies are not locked for reproducible release builds",
                    "dependency_lock_missing",
                    "manifest=package.json lockfile_present=false",
                    "Floating transitive versions can change between audit and release and introduce regressions or supply-chain risk.",
                    "Commit the package-manager lockfile, use frozen/immutable install mode in CI, and review lockfile changes.",
                )
            )
        if api_surface_count and not rate_limit_present:
            results.append(
                self._finding(
                    base,
                    "RELEASE_API_RATE_LIMIT_EVIDENCE_MISSING",
                    "medium",
                    "low",
                    "API routes exist but no rate-limit or throttling evidence was found",
                    "api_rate_limit_evidence_gap",
                    f"api_surface_count={api_surface_count} rate_limit_marker_present=false",
                    "Unauthenticated and costly endpoints can be abused for scraping, credential attacks, resource exhaustion, or unexpected vendor spend.",
                    "Apply endpoint-specific limits at the trusted edge/server, key them by authenticated actor where possible, and test 429 behavior.",
                )
            )
        if auth_surface_present and test_file_count == 0:
            results.append(
                self._finding(
                    base,
                    "RELEASE_AUTH_TEST_EVIDENCE_MISSING",
                    "medium",
                    "low",
                    "Authentication-related code exists but no test files were found",
                    "auth_test_evidence_gap",
                    "auth_surface_present=true test_file_count=0",
                    "Authorization regressions are difficult to catch through visual testing and often affect cross-user or admin boundaries.",
                    "Add negative tests for unauthenticated, wrong-user, wrong-tenant, expired-session, and non-admin access.",
                )
            )
        if (package_json_present or api_surface_count) and not ci_present:
            results.append(
                self._finding(
                    base,
                    "RELEASE_CI_GATE_EVIDENCE_MISSING",
                    "medium",
                    "medium",
                    "No GitHub Actions release-check workflow was found",
                    "ci_gate_evidence_gap",
                    f"package_manifest_present={str(package_json_present).lower()} api_surface_count={api_surface_count} ci_workflow_present=false",
                    "A local review can be bypassed or become stale unless the same checks run on every release candidate.",
                    "Run Guardian with fail_on=high in CI, preserve the signed evidence bundle, and require the job before merge/deploy.",
                )
            )
        return results

    def _finding(
        self,
        root: Path,
        rule_id: str,
        severity: str,
        confidence: str,
        title: str,
        subtype: str,
        evidence: str,
        why: str,
        recommendation: str,
    ) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="release-readiness",
            rule_id=rule_id,
            severity=severity,
            confidence=confidence,
            title=title,
            file=str(root),
            evidence=f"detector_subtype={subtype} {evidence} scheme={evidence_hash_scheme()} raw_returned=false",
            why_it_matters=why,
            recommendation=recommendation,
            audit_depth=3,
            inspected_scope="Local workspace structure and text were checked for release evidence without executing package-manager or deployment commands.",
            not_inspected="This does not query live vulnerability databases, run load tests, inspect cloud policy, or prove that CI is mandatory in repository settings.",
        )


def _production_source(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_SUFFIXES and not any(part.lower() in NON_PRODUCTION_PARTS for part in path.parts)


def _governance_text_relevant(text: str) -> bool:
    lower = text.lower()
    if not any(marker in lower for marker in GOVERNANCE_PREFILTER_MARKERS):
        return False
    return (
        GOVERNED_FIELD_HINT.search(text) is not None
        or AMBIGUOUS_FIELD_HINT.search(text) is not None
        or ENCRYPTION_MARKER.search(text) is not None
        or ACCESS_CONTROL_MARKER.search(text) is not None
        or ACCESS_AUDIT_MARKER.search(text) is not None
        or TRANSFER_GOVERNANCE_MARKER.search(text) is not None
    )


def _control_evidence_file(path: Path) -> bool:
    if any(part.lower() in NON_PRODUCTION_PARTS for part in path.parts):
        return False
    return path.suffix.lower() in CONTROL_EVIDENCE_SUFFIXES or path.name.lower() in {"dockerfile", "compose.yaml", "compose.yml"}


def _declared_field(line: str, names: tuple[str, ...]) -> str | None:
    return _declared_field_from_candidates(_declared_field_candidates(line), names)


def _declared_field_candidates(line: str) -> list[tuple[str, str]]:
    candidates: list[str] = []
    patterns = (
        r"['\"`]\s*([^'\"`]+?)\s*['\"`]\s*:",
        r"['\"`]\s*([^'\"`]+?)\s*['\"`]\s+(?:String|Bytes|Text|varchar|char|text|bytea)\b",
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\??\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>\[\]?| ]*",
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:Column|Field|mapped_column|db\.Column|models\.)",
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s+(?:String|Bytes|Text|varchar|char|text|bytea)\b",
        r"\b(?:String|Bytes|Text|varchar|char|text|bytea)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
    )
    for pattern in patterns:
        candidates.extend(match.group(1) for match in re.finditer(pattern, line, re.IGNORECASE))
    return [(candidate, _field_key(candidate)) for candidate in candidates]


def _declared_field_from_candidates(candidates: list[tuple[str, str]], names: tuple[str, ...]) -> str | None:
    known = _known_field_keys(names)
    for candidate, key in candidates:
        if key in known:
            return candidate
    return None


@lru_cache(maxsize=None)
def _known_field_keys(names: tuple[str, ...]) -> frozenset[str]:
    return frozenset(_field_key(name) for name in names)


def _field_control_state(
    declaration_path: Path,
    declaration_line: int,
    field_name: str,
    control_lines: list[tuple[Path, int, str]],
) -> tuple[bool, bool, bool]:
    correlated = [
        line
        for path, line_no, line in control_lines
        if path == declaration_path
        and (
            _line_mentions_field(line, field_name)
            or (
                declaration_line - 2 <= line_no < declaration_line
                and line.lstrip().startswith("@")
            )
        )
    ]
    return (
        any(ENCRYPTION_MARKER.search(_code_without_string_literals(line)) for line in correlated),
        any(ACCESS_CONTROL_MARKER.search(_code_without_string_literals(line)) and _line_mentions_field(line, field_name) for line in correlated),
        any(ACCESS_AUDIT_MARKER.search(_code_without_string_literals(line)) and _line_mentions_field(line, field_name) for line in correlated),
    )


def _line_mentions_field(line: str, field_name: str) -> bool:
    target = _field_key(field_name)
    if not target:
        return False
    identifiers = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*|[가-힣]+", line)
    return any(_field_key(identifier) == target for identifier in identifiers)


def _field_key(value: str) -> str:
    return "".join(character.lower() for character in str(value) if character.isalnum())


def _code_lines_without_comments(text: str) -> list[str]:
    without_blocks = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    return [_strip_line_comment(line) for line in without_blocks.splitlines()]


def _strip_line_comment(line: str) -> str:
    if "#" not in line and "//" not in line and "--" not in line:
        return line
    quote = ""
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = ""
        elif character in {"'", '"', "`"}:
            quote = character
        elif character == "#":
            return line[:index]
        elif character == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return line[:index]
        elif character == "-" and index + 1 < len(line) and line[index + 1] == "-" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1
    return line


def _code_without_string_literals(line: str) -> str:
    output: list[str] = []
    quote = ""
    escaped = False
    for character in line:
        if escaped:
            output.append(" " if quote else character)
            escaped = False
        elif character == "\\":
            output.append(" " if quote else character)
            escaped = True
        elif quote:
            if character == quote:
                quote = ""
            output.append(" ")
        elif character in {"'", '"', "`"}:
            quote = character
            output.append(" ")
        else:
            output.append(character)
    return "".join(output)
