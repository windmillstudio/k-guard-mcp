from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding
from k_guard_mcp.taint import (
    JS_TS_PROCESS_METHODS,
    JS_TS_SUFFIXES,
    JsTsCommandBindings,
    _js_ts_command_bindings,
    _js_ts_has_process_sink,
)


REQUEST_INPUT = (
    r"(?:req(?:uest)?\.(?:body|query|params|args|form|json|values)|"
    r"request\.(?:args|form|json|values)|params\.[A-Za-z_$]|"
    r"searchParams\.get\s*\(|url\.searchParams\.get\s*\()"
)
REQUEST_MARKERS = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "request.args",
    "request.form",
    "request.json",
    "searchparams.get(",
    "url.searchparams.get(",
)
NON_EXECUTABLE_SUFFIXES = (".md", ".txt", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env", ".sql", ".css", ".scss")


@dataclass(frozen=True)
class AppRiskRule:
    rule_id: str
    severity: str
    confidence: str
    title: str
    subtype: str
    pattern: re.Pattern[str]
    why_it_matters: str
    recommendation: str


RULES = (
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_SQL",
        "critical",
        "high",
        "Request input is interpolated directly into a database query",
        "direct_request_to_sql",
        re.compile(r"(?:\.(?:query|execute|raw|rawQuery)|\b(?:query|execute))\s*\(", re.IGNORECASE),
        "Direct request-to-query construction can allow SQL or query-language injection and bypass data-scope checks.",
        "Use parameterized queries or the ORM query builder, validate identifiers, and add a regression test with hostile metacharacters.",
    ),
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
        "critical",
        "high",
        "Request input reaches a process execution call",
        "direct_request_to_command",
        re.compile(
            rf"(?:\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\()[^\n;]*{REQUEST_INPUT}",
            re.IGNORECASE,
        ),
        "A request-controlled command or argument can become remote command execution.",
        "Replace shell construction with a fixed executable and strict argument allowlist; never pass request text through a shell.",
    ),
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT",
        "medium",
        "medium",
        "Request input reaches a process argument boundary",
        "direct_request_to_process_argument",
        re.compile(rf"(?:\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\()[^\n;]*{REQUEST_INPUT}", re.IGNORECASE),
        "A fixed executable is safer than a shell, but attacker-controlled flags or operands can still change command behavior.",
        "Use an argument allowlist, reject option prefixes where inappropriate, and keep shell mode disabled.",
    ),
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_FILE_PATH",
        "high",
        "medium",
        "Request input reaches a filesystem path operation",
        "direct_request_to_file_path",
        re.compile(
            rf"(?:readFile|readFileSync|sendFile|createReadStream|writeFile|writeFileSync|\bopen|Path)\s*\([^\n;]*{REQUEST_INPUT}",
            re.IGNORECASE,
        ),
        "Request-controlled paths can allow traversal, arbitrary file reads, or writes outside the intended directory.",
        "Resolve against a fixed root, reject absolute and parent paths, and authorize the requested object before file access.",
    ),
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST",
        "high",
        "medium",
        "Request input controls an outbound request target",
        "direct_request_to_outbound_url",
        re.compile(
            rf"(?:\bfetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen)\s*\([^\n;]*{REQUEST_INPUT}",
            re.IGNORECASE,
        ),
        "A caller-controlled URL can become SSRF and reach cloud metadata, internal services, or local-only admin endpoints.",
        "Use an explicit scheme/host allowlist, resolve and validate IP ranges, disable redirects, and block loopback/private/link-local targets.",
    ),
    AppRiskRule(
        "WEB_UNTRUSTED_INPUT_TO_HTML",
        "high",
        "high",
        "Request input is inserted into an HTML execution sink",
        "direct_request_to_html_sink",
        re.compile(
            rf"(?:dangerouslySetInnerHTML[^\n]*__html\s*:|\.innerHTML\s*=|document\.write\s*\()[^\n;]*{REQUEST_INPUT}",
            re.IGNORECASE,
        ),
        "Untrusted HTML can execute script in another user's browser and steal sessions or alter transactions.",
        "Render as text or sanitize with a maintained allowlist sanitizer, then enforce a restrictive Content Security Policy.",
    ),
    AppRiskRule(
        "API_MASS_ASSIGNMENT_REQUEST_BODY",
        "high",
        "high",
        "Whole request body is passed to a persistence mutation",
        "request_body_mass_assignment",
        re.compile(
            r"(?:\.create|\.update|\.insert|\.upsert|findOneAndUpdate|updateOne|updateMany)\s*\([^\n;]*(?:data\s*:\s*)?(?:req(?:uest)?\.body|request\.(?:json|data))(?![.\[])\b",
            re.IGNORECASE,
        ),
        "Mass assignment lets callers set fields such as role, owner, tenant, approval state, or account balance unless every field is constrained.",
        "Map an explicit allowlist DTO into the write, derive ownership and privileged fields from the authenticated server context, and test forbidden fields.",
    ),
    AppRiskRule(
        "API_OPEN_REDIRECT_REQUEST_INPUT",
        "high",
        "medium",
        "Request input controls a redirect destination",
        "request_controlled_redirect",
        re.compile(rf"(?:redirect|NextResponse\.redirect|Response\.redirect)\s*\([^\n;]*{REQUEST_INPUT}", re.IGNORECASE),
        "Open redirects support phishing and can leak authorization codes or tokens through crafted return URLs.",
        "Allow only relative paths or exact trusted origins and reject encoded, protocol-relative, and nested redirect values.",
    ),
    AppRiskRule(
        "AUTH_TOKEN_IN_BROWSER_STORAGE",
        "high",
        "high",
        "Authentication material is written to browser storage",
        "browser_storage_auth_token",
        re.compile(
            r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"](?:access[_-]?token|refresh[_-]?token|auth[_-]?token|jwt|session|credential)s?['\"]",
            re.IGNORECASE,
        ),
        "Browser storage is readable by injected script, so an XSS can directly steal long-lived authentication material.",
        "Prefer short-lived server sessions in Secure, HttpOnly, SameSite cookies and rotate refresh credentials after suspected exposure.",
    ),
    AppRiskRule(
        "AUTH_COOKIE_SECURITY_FLAG_DISABLED",
        "high",
        "high",
        "A session or authentication cookie explicitly disables a security flag",
        "cookie_security_flag_disabled",
        re.compile(
            r"(?:setCookie|cookies?\.set|res\.cookie|session)[^\n]*(?:httpOnly\s*:\s*false|secure\s*:\s*false)",
            re.IGNORECASE,
        ),
        "Weak cookie flags make session theft and cross-site request abuse easier.",
        "Use Secure and HttpOnly for authentication cookies and choose SameSite=Lax/Strict unless a reviewed cross-site flow requires None with Secure.",
    ),
    AppRiskRule(
        "AUTH_PLAINTEXT_PASSWORD_COMPARISON",
        "critical",
        "high",
        "Password appears to be compared or queried as plaintext",
        "plaintext_password_comparison",
        re.compile(
            r"(?:password\s*(?:===|==)\s*(?:user|account|record|dbUser)\.password|(?:user|account|record|dbUser)\.password\s*(?:===|==)\s*password|password\s*:\s*(?:req(?:uest)?\.body|request\.(?:json|data))\.password)",
            re.IGNORECASE,
        ),
        "Plaintext password comparison usually means reversible or unhashed credential storage and turns a data leak into immediate account compromise.",
        "Store only a modern salted password hash, verify with the library's constant-time function, and migrate existing plaintext credentials.",
    ),
    AppRiskRule(
        "AUTH_JWT_DECODE_WITHOUT_VERIFY",
        "high",
        "high",
        "JWT decode is used on request data without signature verification",
        "jwt_decode_without_verify",
        re.compile(
            rf"\b(?:jwt|jsonwebtoken)\.decode\s*\([^\n;]*(?:{REQUEST_INPUT}|verify\s*=\s*(?:False|0)|verify\s*:\s*false|verify_signature[\"']?\s*[:=]\s*(?:False|false|0))",
            re.IGNORECASE,
        ),
        "Decoding a JWT does not prove its signature, issuer, audience, or expiry, so forged claims may cross an authorization boundary.",
        "Use a verification API with an algorithm allowlist, issuer, audience, and expiry checks before trusting any claim.",
    ),
    AppRiskRule(
        "WEB_UNRESTRICTED_FILE_UPLOAD_REVIEW",
        "medium",
        "medium",
        "File upload middleware has no visible type or size restriction",
        "upload_without_visible_limits",
        re.compile(r"multer\s*\(\s*\{(?![^\n]*(?:limits|fileFilter))[^\n]*\}", re.IGNORECASE),
        "Unrestricted uploads can exhaust storage or memory and may place executable or active content in a public location.",
        "Set byte/count limits, verify content by signature, generate server-side names, and keep uploads outside executable/public roots.",
    ),
)

RULE_PREFILTERS = {
    "WEB_UNTRUSTED_INPUT_TO_SQL": ("query", "execute", ".raw"),
    "WEB_UNTRUSTED_INPUT_TO_COMMAND": ("exec", "spawn", "os.system", "subprocess."),
    "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT": ("spawn", "execfile", "subprocess."),
    "WEB_UNTRUSTED_INPUT_TO_FILE_PATH": ("readfile", "sendfile", "createreadstream", "writefile", "open(", "path("),
    "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST": ("fetch", "axios.", "requests.", "httpx.", "urlopen"),
    "WEB_UNTRUSTED_INPUT_TO_HTML": ("dangerouslysetinnerhtml", "innerhtml", "document.write"),
    "API_MASS_ASSIGNMENT_REQUEST_BODY": (".create", ".update", ".insert", ".upsert", "findoneandupdate", "updateone", "updatemany"),
    "API_OPEN_REDIRECT_REQUEST_INPUT": ("redirect",),
    "AUTH_TOKEN_IN_BROWSER_STORAGE": ("localstorage", "sessionstorage"),
    "AUTH_COOKIE_SECURITY_FLAG_DISABLED": ("setcookie", "cookie", "session"),
    "AUTH_PLAINTEXT_PASSWORD_COMPARISON": ("password",),
    "AUTH_JWT_DECODE_WITHOUT_VERIFY": ("jwt", "jsonwebtoken"),
    "WEB_UNRESTRICTED_FILE_UPLOAD_REVIEW": ("multer",),
}
APP_RISK_SIGNAL_MARKERS = frozenset(marker for markers in RULE_PREFILTERS.values() for marker in markers)


class AppRiskDetector:
    """High-signal web/API/auth review rules with raw-free line evidence."""

    def __init__(self, id_factory: IdFactory | None = None, max_findings_per_rule: int = 5) -> None:
        self.ids = id_factory or IdFactory()
        self.max_findings_per_rule = max_findings_per_rule

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        if str(file or "").lower().endswith(NON_EXECUTABLE_SUFFIXES):
            return []
        lower_text = text.lower()
        if not any(marker in lower_text for marker in APP_RISK_SIGNAL_MARKERS):
            return []
        command_bindings = (
            _js_ts_command_bindings(text)
            if any(str(file or "").lower().endswith(suffix) for suffix in JS_TS_SUFFIXES)
            else None
        )
        pyjwt_direct_decode_lines = (
            _python_proven_pyjwt_direct_decode_lines(text)
            if str(file or "").lower().endswith(".py") and "jwt" in lower_text and "decode" in lower_text
            else frozenset()
        )
        findings: list[Finding] = []
        counts: Counter[str] = Counter()
        for line_no, line in enumerate(_uncommented_lines(text), start=1):
            if not line.strip():
                continue
            string_ranges = _string_ranges(line[:8192])
            for rule in RULES:
                if counts[rule.rule_id] >= self.max_findings_per_rule or not _matches_rule(
                    rule,
                    line,
                    file,
                    string_ranges,
                    command_bindings,
                    line_no,
                    pyjwt_direct_decode_lines,
                ):
                    continue
                counts[rule.rule_id] += 1
                findings.append(self._finding(rule, line, line_no, file))
        return findings

    def _finding(self, rule: AppRiskRule, line: str, line_no: int, file: str | None) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="app-risk",
            rule_id=rule.rule_id,
            severity=rule.severity,
            confidence=rule.confidence,
            title=rule.title,
            file=file,
            line_start=line_no,
            line_end=line_no,
            evidence=(
                f"detector_subtype={rule.subtype} line_hash={evidence_hash(line)} "
                f"scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            why_it_matters=rule.why_it_matters,
            recommendation=rule.recommendation,
            audit_depth=4,
            inspected_scope="A deterministic source-line rule matched a direct request-to-dangerous-sink or explicit weak-control pattern.",
            not_inspected="This rule does not prove exploitability, resolve every alias or middleware, or replace framework-aware runtime authorization tests.",
        )


def _matches_rule(
    rule: AppRiskRule,
    line: str,
    file: str | None,
    string_ranges: list[tuple[int, int]] | None = None,
    command_bindings: JsTsCommandBindings | None = None,
    line_no: int | None = None,
    pyjwt_direct_decode_lines: frozenset[int] = frozenset(),
) -> bool:
    direct_pyjwt_decode = (
        rule.rule_id == "AUTH_JWT_DECODE_WITHOUT_VERIFY"
        and line_no in pyjwt_direct_decode_lines
    )
    lower = line[:8192].lower()
    if not direct_pyjwt_decode and not any(marker in lower for marker in RULE_PREFILTERS[rule.rule_id]):
        return False
    if not direct_pyjwt_decode and not _pattern_starts_in_code(rule.pattern, line[:8192], string_ranges):
        return False
    if rule.rule_id == "WEB_UNTRUSTED_INPUT_TO_SQL":
        return _linear_unsafe_sql_match(line)
    if rule.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND":
        if command_bindings is not None and not _js_ts_has_process_sink(
            line[:8192],
            command_bindings,
            JS_TS_PROCESS_METHODS,
            line_no,
        ):
            return False
        return _unsafe_command_execution(line)
    if rule.rule_id == "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT":
        if command_bindings is not None and not _js_ts_has_process_sink(
            line[:8192],
            command_bindings,
            JS_TS_PROCESS_METHODS,
            line_no,
        ):
            return False
        return not _unsafe_command_execution(line)
    if rule.rule_id == "AUTH_JWT_DECODE_WITHOUT_VERIFY" and str(file or "").lower().endswith(".py"):
        if direct_pyjwt_decode:
            return True
        compact = line.lower().replace(" ", "")
        return any(marker in compact for marker in ("verify=false", "verify=0", "verify_signature\":false", "verify_signature':false"))
    return True


def _python_proven_pyjwt_direct_decode_lines(text: str) -> frozenset[int]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return frozenset()

    imports: list[tuple[ast.ImportFrom, str]] = []
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom) or statement.level != 0 or statement.module != "jwt":
            continue
        for imported in statement.names:
            if imported.name == "decode":
                imports.append((statement, imported.asname or imported.name))
    if len(imports) != 1:
        return frozenset()

    import_node, binding = imports[0]
    if sum((imported.asname or imported.name) == binding for imported in import_node.names) != 1:
        return frozenset()
    if any(
        node is not import_node and _python_ast_binds_name(node, binding)
        for node in ast.walk(tree)
    ):
        return frozenset()

    return frozenset(
        call.lineno
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == binding
        and _python_call_disables_jwt_verification(call)
    )


def _python_ast_binds_name(node: ast.AST, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
    if isinstance(node, ast.arg):
        return node.arg == name
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if isinstance(node, ast.Import):
        return any((imported.asname or imported.name.split(".", 1)[0]) == name for imported in node.names)
    if isinstance(node, ast.ImportFrom):
        return any((imported.asname or imported.name) == name for imported in node.names)
    if isinstance(node, ast.ExceptHandler):
        return node.name == name
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return name in node.names
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    return False


def _python_call_disables_jwt_verification(call: ast.Call) -> bool:
    if any(keyword.arg is None for keyword in call.keywords):
        return False

    verify_values = [keyword.value for keyword in call.keywords if keyword.arg == "verify"]
    options_values = [keyword.value for keyword in call.keywords if keyword.arg == "options"]
    if len(verify_values) > 1 or len(options_values) > 1:
        return False

    verify_disabled = False
    if verify_values:
        if not _python_literal_false(verify_values[0]):
            return False
        verify_disabled = True

    options_disabled = False
    if options_values:
        options = options_values[0]
        if (
            not isinstance(options, ast.Dict)
            or any(key is None for key in options.keys)
            or not all(_python_literal_expression(value) for value in options.values)
        ):
            return False
        signature_values = [
            value
            for key, value in zip(options.keys, options.values, strict=True)
            if isinstance(key, ast.Constant)
            and type(key.value) is str
            and key.value == "verify_signature"
        ]
        if len(signature_values) > 1:
            return False
        if signature_values:
            if not _python_literal_false(signature_values[0]):
                return False
            options_disabled = True

    return verify_disabled or options_disabled


def _python_literal_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _python_literal_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_python_literal_expression(value) for value in node.elts)
    if isinstance(node, ast.Dict):
        return (
            all(key is not None and _python_literal_expression(key) for key in node.keys)
            and all(_python_literal_expression(value) for value in node.values)
        )
    return False


def _linear_unsafe_sql_match(line: str) -> bool:
    lower = line[:8192].lower()
    input_positions = [lower.find(marker) for marker in REQUEST_MARKERS if marker in lower]
    if not input_positions:
        return False
    sink_match = re.search(r"(?:\.(?:query|execute|raw|rawquery)|\b(?:query|execute))\s*\(", lower)
    if not sink_match:
        return False
    input_pos = min(position for position in input_positions if position >= 0)
    first_comma = lower.find(",", sink_match.end())
    request_is_first_argument = first_comma < 0 or input_pos < first_comma
    interpolated = "${" in lower[sink_match.end():] or bool(re.search(r"[+].*(?:req\.|request\.)|(?:req\.|request\.).*[+]", lower[sink_match.end():]))
    return request_is_first_argument or interpolated


def _unsafe_command_execution(line: str) -> bool:
    lower = line[:8192].lower()
    if re.search(r"\b(?:exec|execsync)\s*\(|os\.system\s*\(", lower):
        return True
    sink = re.search(r"(?:\b(?:spawn|spawnsync|execfile|execfilesync)\s*\(|subprocess\.(?:run|call|popen|check_output)\s*\()", lower)
    if not sink:
        return False
    if re.search(r"\bshell\s*=\s*true\b|\bshell\s*:\s*true\b", lower[sink.start():]):
        return True
    input_positions = [lower.find(marker, sink.end()) for marker in REQUEST_MARKERS if lower.find(marker, sink.end()) >= 0]
    if not input_positions:
        return False
    input_pos = min(input_positions)
    first_comma = lower.find(",", sink.end())
    return first_comma < 0 or input_pos < first_comma


def _pattern_starts_in_code(
    pattern: re.Pattern[str],
    line: str,
    string_ranges: list[tuple[int, int]] | None = None,
) -> bool:
    string_ranges = _string_ranges(line) if string_ranges is None else string_ranges
    return any(not any(start <= match.start() < end for start, end in string_ranges) for match in pattern.finditer(line))


def _string_ranges(line: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    quote = ""
    start = -1
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                ranges.append((start, index + 1))
                quote = ""
        elif character in {"'", '"', "`"}:
            quote = character
            start = index
    if quote:
        ranges.append((start, len(line)))
    return ranges


def _uncommented_lines(text: str) -> list[str]:
    lines: list[str] = []
    in_block = False
    for original in text.splitlines():
        output: list[str] = []
        quote = ""
        escaped = False
        index = 0
        while index < len(original):
            if in_block:
                closing = original.find("*/", index)
                if closing < 0:
                    index = len(original)
                    continue
                in_block = False
                index = closing + 2
                continue
            character = original[index]
            if escaped:
                output.append(character)
                escaped = False
            elif character == "\\":
                output.append(character)
                escaped = True
            elif quote:
                output.append(character)
                if character == quote:
                    quote = ""
            elif character in {"'", '"', "`"}:
                quote = character
                output.append(character)
            elif original.startswith("/*", index):
                in_block = True
                index += 2
                continue
            elif original.startswith("//", index) or character == "#":
                break
            else:
                output.append(character)
            index += 1
        lines.append("".join(output))
    return lines
