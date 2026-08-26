from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from k_guard_mcp.collector import is_semantic_noise_asset
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.java_flow import JavaFlowParseError, scan_java_sql_flows
from k_guard_mcp.models import Finding
from k_guard_mcp.taint import (
    JS_TS_SUFFIXES,
    _js_ts_assignment,
    _js_ts_command_bindings,
    _js_ts_declared_params,
    _js_ts_function_scopes,
    _js_ts_has_process_sink,
    _js_ts_sink_relevant_expression,
)


SOURCE_MARKERS = re.compile(
    r"(?:req(?:uest)?\.(?:body|query|params|cookies?)|request\.(?:args|form|json|values)|"
    r"\$_(?:GET|POST|REQUEST|COOKIE)|params\s*\[|@RequestParam|@PathVariable|\.URL\.Query\(\)\.Get\()",
    re.IGNORECASE,
)
IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
SQL_SINK = re.compile(r"\b(?:query|execute|executeQuery|executeUpdate|raw|rawQuery)\s*\(", re.IGNORECASE)
DYNAMIC_CODE_SINK = re.compile(r"\b(?:eval|Function)\s*\(")


@dataclass(frozen=True)
class _Signal:
    rule_id: str
    severity: str
    confidence: str
    title: str
    subtype: str
    line: int
    why: str
    recommendation: str


class PolyglotRiskDetector:
    """Bounded source-to-sink checks for common vibe-code backend languages."""

    def __init__(
        self,
        id_factory: IdFactory | None = None,
        max_findings_per_rule: int = 8,
        *,
        enable_java_servlet_xss_observe: bool = True,
        enable_java_servlet_xss_html_encoder_suppression: bool = True,
        enable_java_servlet_xss_html_encoder_helper_suppression: bool = True,
        enable_java_servlet_xss_constant_ternary_suppression: bool = True,
        enable_java_servlet_xss_static_switch_suppression: bool = True,
        enable_java_servlet_xss_static_if_suppression: bool = True,
    ) -> None:
        self.ids = id_factory or IdFactory()
        self.max_findings_per_rule = max_findings_per_rule
        self.enable_java_servlet_xss_observe = enable_java_servlet_xss_observe
        self.enable_java_servlet_xss_html_encoder_suppression = (
            enable_java_servlet_xss_html_encoder_suppression
        )
        self.enable_java_servlet_xss_html_encoder_helper_suppression = (
            enable_java_servlet_xss_html_encoder_helper_suppression
        )
        self.enable_java_servlet_xss_constant_ternary_suppression = (
            enable_java_servlet_xss_constant_ternary_suppression
        )
        self.enable_java_servlet_xss_static_switch_suppression = (
            enable_java_servlet_xss_static_switch_suppression
        )
        self.enable_java_servlet_xss_static_if_suppression = enable_java_servlet_xss_static_if_suppression

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        if is_semantic_noise_asset(file, text):
            return []
        suffix = Path(str(file or "source")).suffix.casefold()
        signals: list[_Signal] = []
        if suffix in JS_TS_SUFFIXES:
            signals.extend(_scan_js_ts(text))
        elif suffix == ".java":
            signals.extend(
                _scan_java_kotlin(
                    text,
                    ast_sql=True,
                    enable_java_servlet_xss_observe=self.enable_java_servlet_xss_observe,
                    enable_java_servlet_xss_html_encoder_suppression=(
                        self.enable_java_servlet_xss_html_encoder_suppression
                    ),
                    enable_java_servlet_xss_html_encoder_helper_suppression=(
                        self.enable_java_servlet_xss_html_encoder_helper_suppression
                    ),
                    enable_java_servlet_xss_constant_ternary_suppression=(
                        self.enable_java_servlet_xss_constant_ternary_suppression
                    ),
                    enable_java_servlet_xss_static_switch_suppression=(
                        self.enable_java_servlet_xss_static_switch_suppression
                    ),
                    enable_java_servlet_xss_static_if_suppression=(
                        self.enable_java_servlet_xss_static_if_suppression
                    ),
                )
            )
        elif suffix == ".kt":
            signals.extend(_scan_java_kotlin(text))
        elif suffix == ".go":
            signals.extend(_scan_go(text))
        elif suffix == ".php":
            signals.extend(_scan_php(text))
        elif suffix == ".rb":
            signals.extend(_scan_ruby(text))

        counts: Counter[str] = Counter()
        seen: set[tuple[str, int, str]] = set()
        findings: list[Finding] = []
        lines = text.splitlines()
        for signal in sorted(signals, key=lambda item: (item.line, item.rule_id, item.subtype)):
            key = (signal.rule_id, signal.line, signal.subtype)
            if key in seen or counts[signal.rule_id] >= self.max_findings_per_rule:
                continue
            seen.add(key)
            counts[signal.rule_id] += 1
            raw_line = lines[signal.line - 1] if 0 < signal.line <= len(lines) else ""
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="polyglot-flow",
                    rule_id=signal.rule_id,
                    severity=signal.severity,
                    confidence=signal.confidence,
                    title=signal.title,
                    file=file,
                    line_start=signal.line,
                    line_end=signal.line,
                    evidence=(
                        f"detector_subtype={signal.subtype} line_hash={evidence_hash(raw_line)} "
                        f"scheme={evidence_hash_scheme()} raw_returned=false"
                    ),
                    why_it_matters=signal.why,
                    recommendation=signal.recommendation,
                    audit_depth=4,
                    inspected_scope="A bounded language-aware pass tracked request or route identifiers into a security-sensitive operation in this source file.",
                    not_inspected="This pass does not prove runtime exploitability, resolve arbitrary reflection or dependency injection, or replace an authorization test with two real principals.",
                )
            )
        return findings


def _scan_js_ts(text: str) -> list[_Signal]:
    lines = text.splitlines()
    analysis_lines = _strip_c_style_comments(lines)
    scope_ids, scope_parents, _scope_analysis_limited = _js_ts_function_scopes(analysis_lines)
    command_bindings = _js_ts_command_bindings("\n".join(analysis_lines))
    tainted: dict[int, set[str]] = {0: set()}
    bindings: dict[int, set[str]] = {0: set()}
    signals: list[_Signal] = []
    for line_no, line in enumerate(analysis_lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        scope_id = scope_ids[line_no - 1]
        tainted.setdefault(scope_id, set())
        bindings.setdefault(scope_id, set()).update(_js_ts_declared_params(line))
        code = _strip_line_comment(line)
        assignment = _js_ts_assignment(code.strip())
        if assignment:
            names, expression = assignment
            declaration = bool(re.search(r"\b(?:const|let|var)\b", code))
            if declaration:
                bindings[scope_id].update(names)
            if SOURCE_MARKERS.search(expression) or _scope_mentions_any(
                _strip_string_literals(expression), scope_id, tainted, bindings, scope_parents
            ):
                tainted[scope_id].update(names)
            else:
                tainted[scope_id].difference_update(names)
        if DYNAMIC_CODE_SINK.search(code) and (
            SOURCE_MARKERS.search(code) or _scope_mentions_any(code, scope_id, tainted, bindings, scope_parents)
        ):
            signals.append(
                _critical(
                    "WEB_UNTRUSTED_INPUT_TO_CODE_EXECUTION",
                    "Request input reaches dynamic code execution",
                    "js_ts_request_to_eval",
                    line_no,
                    "Dynamic evaluation turns attacker-controlled text into server or browser code.",
                    "Remove eval/new Function and parse the expected value with a strict schema or dedicated parser.",
                )
            )
        if SQL_SINK.search(code) and _scope_mentions_any(
            _strip_string_literals(_js_ts_sink_relevant_expression(code, "sql")), scope_id, tainted, bindings, scope_parents
        ):
            signals.append(
                _critical(
                    "WEB_UNTRUSTED_INPUT_TO_SQL",
                    "Request-derived text reaches a SQL execution API",
                    "js_ts_bounded_request_to_sql",
                    line_no,
                    "Building SQL from request-derived text can alter the query and bypass data boundaries.",
                    "Use bind parameters or a query builder and add hostile-input regression tests.",
                )
            )
        command_expression = _js_ts_sink_relevant_expression(code, "command")
        if _js_ts_has_process_sink(code, command_bindings, line_no=line_no) and (
            SOURCE_MARKERS.search(command_expression)
            or _scope_mentions_any(command_expression, scope_id, tainted, bindings, scope_parents)
        ):
            signals.append(
                _critical(
                    "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                    "Request-derived text reaches command execution",
                    "js_ts_bounded_request_to_command",
                    line_no,
                    "A request-controlled command can become remote command execution.",
                    "Use a fixed executable and an allowlisted argument vector without a shell.",
                )
            )

    lower = text.casefold()
    if "redirect" in lower and re.search(r"\b(?:allowed|trusted|allowlist)[A-Za-z0-9_$]*\b", text, re.IGNORECASE):
        for line_no, line in enumerate(lines, start=1):
            if re.search(r"\b(?:url|uri|target|destination)\.includes\s*\(\s*(?:allowed|trusted|allowlist)", line, re.IGNORECASE):
                signals.append(
                    _Signal(
                        "API_OPEN_REDIRECT_WEAK_ALLOWLIST",
                        "high",
                        "high",
                        "Redirect allowlist uses substring containment",
                        "redirect_substring_allowlist",
                        line_no,
                        "A hostile URL can contain a trusted URL as a substring while still sending the user to an attacker-controlled origin.",
                        "Parse the URL and compare normalized scheme, host, port, and path against exact approved destinations.",
                    )
                )
    return signals


def _scan_java_kotlin(
    text: str,
    *,
    ast_sql: bool = False,
    enable_java_servlet_xss_observe: bool = False,
    enable_java_servlet_xss_html_encoder_suppression: bool = False,
    enable_java_servlet_xss_html_encoder_helper_suppression: bool = False,
    enable_java_servlet_xss_constant_ternary_suppression: bool = False,
    enable_java_servlet_xss_static_switch_suppression: bool = False,
    enable_java_servlet_xss_static_if_suppression: bool = False,
) -> list[_Signal]:
    signals: list[_Signal] = []
    if ast_sql:
        try:
            signals.extend(
                _critical(
                    "WEB_UNTRUSTED_INPUT_TO_SQL",
                    "Servlet or Spring input reaches a SQL execution API",
                    flow.subtype,
                    flow.line,
                    "A request-derived SQL string can change query structure and expose or modify data.",
                    "Use PreparedStatement placeholders and bind every request-derived value separately.",
                )
                for flow in scan_java_sql_flows(text)
            )
        except JavaFlowParseError:
            ast_sql = False
    methods = list(_brace_methods(text))
    sql_helpers: dict[str, tuple[set[str], int]] = {}
    for helper_start, helper_signature, helper_body in methods:
        helper_name, helper_params = _method_name_and_params(helper_signature)
        if not helper_name or not helper_params:
            continue
        for offset, helper_line in enumerate(helper_body.splitlines()):
            if _is_java_sql_sink(helper_line) and _mentions_any(
                _strip_string_literals(_call_arguments(helper_line)), helper_params
            ):
                sql_helpers[helper_name] = (helper_params, helper_start + offset)
                break
    html_encoder_helpers = (
        _java_known_html_encoder_helpers(methods)
        if enable_java_servlet_xss_observe
        and enable_java_servlet_xss_html_encoder_suppression
        and enable_java_servlet_xss_html_encoder_helper_suppression
        else {}
    )
    constant_ternary_helpers = (
        _java_constant_ternary_safe_helpers(methods)
        if enable_java_servlet_xss_observe and enable_java_servlet_xss_constant_ternary_suppression
        else {}
    )
    static_switch_helpers = (
        _java_static_switch_safe_helpers(methods)
        if enable_java_servlet_xss_observe and enable_java_servlet_xss_static_switch_suppression
        else {}
    )
    static_if_helpers = (
        _java_static_if_safe_helpers(methods)
        if enable_java_servlet_xss_observe and enable_java_servlet_xss_static_if_suppression
        else {}
    )

    for start, signature, body in methods:
        tainted = set(
            re.findall(
                r"@(?:RequestParam|PathVariable|RequestHeader|CookieValue)(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:[\w<>?,.\[\]]+\s+)+([A-Za-z_$][\w$]*)",
                signature,
                re.IGNORECASE,
            )
        )
        request_objects = set(re.findall(r"\bHttpServletRequest\s+([A-Za-z_$][\w$]*)", signature))
        response_objects = set(re.findall(r"\bHttpServletResponse\s+([A-Za-z_$][\w$]*)", signature))
        body_lines = body.splitlines()
        analysis_lines = _strip_c_style_comments(body_lines)
        html_response_objects = (
            _java_html_response_objects(analysis_lines, response_objects)
            if enable_java_servlet_xss_observe
            else set()
        )
        xss_tainted: set[str] = set()
        static_values: dict[str, int | bool] = {}
        for line in analysis_lines:
            _java_record_static_value(line, static_values)
            assignment = re.search(r"\b(?:[\w<>?,.\[\]]+\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$", line)
            if assignment and (
                any(f"{name}.getParameter" in assignment.group(2) for name in request_objects)
                or _mentions_any(assignment.group(2), tainted)
            ):
                tainted.add(assignment.group(1))
            if assignment and enable_java_servlet_xss_observe:
                name, expression = assignment.group(1), assignment.group(2)
                if _java_known_html_encoder_helper_call(
                    expression,
                    helpers=html_encoder_helpers,
                    request_objects=request_objects,
                    tainted=xss_tainted,
                ):
                    xss_tainted.discard(name)
                elif _java_constant_ternary_safe_helper_call(
                    expression,
                    helpers=constant_ternary_helpers,
                    tainted=xss_tainted,
                ):
                    xss_tainted.discard(name)
                elif _java_static_switch_safe_helper_call(
                    expression,
                    helpers=static_switch_helpers,
                    tainted=xss_tainted,
                ):
                    xss_tainted.discard(name)
                elif _java_static_if_safe_helper_call(
                    expression,
                    helpers=static_if_helpers,
                    tainted=xss_tainted,
                ):
                    xss_tainted.discard(name)
                elif (
                    enable_java_servlet_xss_constant_ternary_suppression
                    and (
                        selected := _java_constant_ternary_selected_expression(
                            expression,
                            static_values,
                        )
                    ) is not None
                ):
                    if _java_expression_is_tainted(selected, request_objects, xss_tainted):
                        xss_tainted.add(name)
                    else:
                        xss_tainted.discard(name)
                elif enable_java_servlet_xss_html_encoder_suppression and _java_direct_html_encoder(
                    expression,
                    request_objects=request_objects,
                    tainted=xss_tainted,
                ):
                    xss_tainted.discard(name)
                elif _java_servlet_request_source(expression, request_objects) or _mentions_any(
                    _strip_string_literals(expression), xss_tainted
                ):
                    xss_tainted.add(name)
                else:
                    xss_tainted.discard(name)
        for offset, line in enumerate(analysis_lines):
            if not ast_sql and _is_java_sql_sink(line) and _mentions_any(
                _strip_string_literals(_call_arguments(line)), tainted
            ):
                signals.append(
                    _critical(
                        "WEB_UNTRUSTED_INPUT_TO_SQL",
                        "Spring/servlet input reaches a SQL execution API",
                        "java_bounded_request_to_sql",
                        start + offset,
                        "A request-derived SQL string can change query structure and expose or modify data.",
                        "Use PreparedStatement placeholders and bind every request-derived value separately.",
                    )
                )
            if enable_java_servlet_xss_observe and _java_servlet_html_sink_is_tainted(
                line,
                response_objects=html_response_objects,
                request_objects=request_objects,
                tainted=xss_tainted,
            ):
                signals.append(
                    _Signal(
                        "WEB_UNTRUSTED_INPUT_TO_HTML",
                        "medium",
                        "medium",
                        "Servlet request value reaches an HTML response writer",
                        "java_servlet_bounded_html_response_observe",
                        start + offset,
                        "A request-derived value is emitted through a servlet HTML response path without a visible HTML encoder or sanitizer.",
                        "Encode the value for the HTML context or use a maintained allowlist sanitizer before writing the response, then add a hostile-input regression test.",
                    )
                )
            for helper_name in sql_helpers:
                call = re.search(rf"\b{re.escape(helper_name)}\s*\(([^)]*)\)", line)
                if not ast_sql and call and _mentions_any(_strip_string_literals(call.group(1)), tainted):
                    signals.append(
                        _critical(
                            "WEB_UNTRUSTED_INPUT_TO_SQL",
                            "Spring/servlet input reaches a SQL helper",
                            "java_bounded_interprocedural_request_to_sql",
                            start + offset,
                            "A request value crosses a same-file helper boundary and reaches a SQL execution API.",
                            "Use PreparedStatement placeholders in the helper and pass the value separately from SQL text.",
                        )
                    )

        annotation_window = text[max(0, text.find(signature) - 400) : text.find(signature)] if signature else ""
        method_text = f"{annotation_window}\n{signature}\n{body}"
        privileged_persistence_line = _java_privileged_request_body_persistence_line(
            signature,
            body,
            annotation_window,
            method_text,
        )
        if privileged_persistence_line is not None:
            signals.append(
                _Signal(
                    "API_PRIVILEGED_FIELD_MASS_ASSIGNMENT",
                    "high",
                    "medium",
                    "Privileged request body is persisted without a visible policy",
                    "java_spring_privileged_field_mass_assignment_observe",
                    start + privileged_persistence_line,
                    "A request body is saved on a route named for privileged access without a visible authorization policy or an explicit privileged-field reset.",
                    "Use an allowlisted input DTO, set privileged fields server-side, and require a visible role or ownership policy before persistence.",
                )
            )

        path_vars = set(
            re.findall(
                r"@PathVariable(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:[\w<>?,.\[\]]+\s+)+([A-Za-z_$][\w$]*)",
                signature,
                re.IGNORECASE,
            )
        )
        if path_vars and re.search(r"@(Get|Post|Put|Patch|Delete)Mapping\b", annotation_window, re.IGNORECASE):
            cross_account_write_line = _java_cross_account_write_line(
                signature,
                body,
                path_vars,
                method_text,
            )
            if cross_account_write_line is not None:
                signals.append(
                    _Signal(
                        "API_IDOR_ROUTE_PARAM_LOOKUP",
                        "high",
                        "medium",
                        "Cross-account write path lacks a visible authorization policy",
                        "java_spring_cross_account_write_observe",
                        start + cross_account_write_line,
                        "A request body selects a different account than the authenticated identity and the route persists that change without a visible role or ownership authorization check.",
                        "Require an explicit ownership or delegated-role authorization check before applying a cross-account update, then add a denied cross-user integration test.",
                    )
                )
            ownership_signal = any(
                name.lower().endswith("id")
                or re.search(
                    r"(?:user|account|customer|profile|vehicle|car|order|payment|invoice|tenant|owner|member|message|document|record)",
                    name,
                    re.IGNORECASE,
                )
                for name in path_vars
            )
            data_use = any(
                re.search(rf"\b(?:find|get|load|read|update|delete)[A-Za-z0-9_$]*\s*\([^)]*\b{re.escape(name)}\b", body, re.IGNORECASE)
                for name in path_vars
            )
            returns_data = bool(re.search(r"(?:ResponseEntity|\.body\s*\(|return\s+\w+)", method_text, re.IGNORECASE))
            guard = re.search(
                r"(?:@PreAuthorize|principal|authentication|securityContext|currentUser|current_user|ownerId|tenantId|hasPermission|authorize\s*\(|permission)",
                method_text,
                re.IGNORECASE,
            )
            if ownership_signal and data_use and returns_data and not guard:
                line = start + _first_relative_line(body_lines, tuple(path_vars))
                signals.append(
                    _Signal(
                        "API_IDOR_ROUTE_PARAM_LOOKUP",
                        "high",
                        "medium",
                        "Route object id reaches data access without a visible principal scope",
                        "java_spring_path_variable_idor_review",
                        line,
                        "Authentication alone does not prove that the caller owns the object selected by a route id.",
                        "Constrain the service or repository query by the authenticated subject or tenant and test cross-user denial.",
                    )
                )
    return signals


def _java_privileged_request_body_persistence_line(
    signature: str,
    body: str,
    annotation_window: str,
    method_text: str,
) -> int | None:
    """Observe direct persistence of a request body on a privileged Spring route.

    This is intentionally a bounded observer, not proof of a business authorization bug.
    It requires a privileged route name, direct body persistence, no visible policy, and no
    unconditional reset of the body's privileged field before that persistence.
    """

    if not re.search(r"@(?:Post|Put|Patch)Mapping\b", annotation_window, re.IGNORECASE):
        return None
    route_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', annotation_window)
    if not any(
        re.search(r"(?:admin|role|privileg|access[-_]?control)", route, re.IGNORECASE)
        for route in route_literals
    ):
        return None
    if re.search(
        r"(?:@(?:PreAuthorize|Secured|RolesAllowed)\b|has(?:Role|Authority|Permission)\s*\(|"
        r"(?:authorize|authorise|can(?:Edit|Update)|isAdmin|isOwner)\s*\()",
        method_text,
        re.IGNORECASE,
    ):
        return None

    request_bodies = set(
        re.findall(
            r"@RequestBody(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:[\w<>?,.\[\]]+\s+)+([A-Za-z_$][\w$]*)",
            signature,
            re.IGNORECASE,
        )
    )
    if not request_bodies:
        return None

    analysis = _strip_string_literals("\n".join(_strip_c_style_comments(body.splitlines())))
    for request_body in sorted(request_bodies):
        persistence = re.search(
            rf"\.[ \t]*(?:save|persist|insert|update|upsert|create)\s*\(\s*{re.escape(request_body)}\b",
            analysis,
            re.IGNORECASE,
        )
        if persistence is None:
            continue
        if _java_request_body_privilege_is_unconditionally_neutralized(
            analysis,
            request_body=request_body,
            persistence_offset=persistence.start(),
        ):
            continue
        return analysis.count("\n", 0, persistence.start())
    return None


def _java_request_body_privilege_is_unconditionally_neutralized(
    body: str,
    *,
    request_body: str,
    persistence_offset: int,
) -> bool:
    """Accept only a final, direct, unconditional restrictive setter before persistence."""

    before_persistence = body[:persistence_offset]
    # A conditional reset can leave a path that persists the client-supplied privilege, so it
    # never suppresses the observer. The known negative control uses a direct statement.
    if re.search(r"\bif\s*\(", before_persistence, re.IGNORECASE):
        return False
    setters = list(
        re.finditer(
            rf"\b{re.escape(request_body)}\s*\.\s*set(?:Admin|Role|Privilege|Authorities?|Permissions?)"
            r"\s*\(\s*([^)]+?)\s*\)",
            before_persistence,
            re.IGNORECASE,
        )
    )
    if not setters:
        return False
    final_value = setters[-1].group(1).strip()
    return re.fullmatch(
        r"(?:false|0|(?:[A-Za-z_$][\w$]*\.)?(?:USER|GUEST|NONE|UNPRIVILEGED))",
        final_value,
        re.IGNORECASE,
    ) is not None


def _java_cross_account_write_line(
    signature: str,
    body: str,
    path_vars: set[str],
    method_text: str,
) -> int | None:
    """Return the first cross-account write line for a deliberately narrow Spring review signal."""

    request_bodies = set(
        re.findall(
            r"@RequestBody(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:[\w<>?,.\[\]]+\s+)+([A-Za-z_$][\w$]*)",
            signature,
            re.IGNORECASE,
        )
    )
    if not request_bodies or not any(_mentions_any(body, {name}) for name in path_vars):
        return None

    # Authentication-only identifiers are intentionally not authorization guards.  We only
    # suppress the observer for a visible delegated-role or ownership policy.
    if re.search(
        r"(?:@(?:PreAuthorize|Secured|RolesAllowed)\b|has(?:Role|Authority|Permission)\s*\(|"
        r"(?:authorize|authorise|can(?:Edit|Update)|isAdmin|isOwner)\s*\()",
        method_text,
        re.IGNORECASE,
    ):
        return None

    auth_names = set(
        re.findall(
            r"\b(?:final\s+)?[\w<>?,.\[\]]+\s+("
            r"(?:auth(?:enticated)?|current|principal|session)[A-Za-z_$]*?(?:id|name)"
            r")\s*=",
            body,
            re.IGNORECASE,
        )
    )
    if not auth_names:
        return None

    persistence = re.search(
        r"\.[ \t]*(?:save|update|delete|put|replace|setValue)\s*\(",
        body,
        re.IGNORECASE,
    )
    if persistence is None:
        return None

    for request_body in sorted(request_bodies):
        identity = rf"\b{re.escape(request_body)}\.get(?:[A-Za-z_$][\w$]*)?Id\s*\(\)"
        for auth_name in sorted(auth_names):
            mismatch = re.search(
                rf"(?:!\s*{identity}\.equals\s*\(\s*{re.escape(auth_name)}\s*\)|"
                rf"{identity}\s*(?:!=|!==)\s*{re.escape(auth_name)}|"
                rf"{re.escape(auth_name)}\s*(?:!=|!==)\s*{identity})",
                body,
                re.IGNORECASE,
            )
            if mismatch is not None:
                if _java_cross_account_mismatch_is_explicitly_rejected(
                    body,
                    identity=identity,
                    mismatch=mismatch.re,
                ):
                    return None
                return body.count("\n", 0, mismatch.start())
    return None


def _java_cross_account_mismatch_is_explicitly_rejected(
    body: str,
    *,
    identity: str,
    mismatch: re.Pattern[str],
) -> bool:
    """Recognize a complete, visible denial branch without treating auth IDs as ownership proof."""

    analysis = _strip_string_literals("\n".join(_strip_c_style_comments(body.splitlines())))
    rejection = re.compile(
        r"\breturn\b[^;{}]*(?:\b(?:forbidden|unauthori[sz]ed|access[_\s-]?denied|"
        r"denied|failure|failed)\b|HttpStatus\.(?:FORBIDDEN|UNAUTHORIZED))",
        re.IGNORECASE,
    )
    persistence = re.compile(r"\.[ \t]*(?:save|update|delete|put|replace|setValue)\s*\(", re.IGNORECASE)
    denied = False

    for branch in re.finditer(r"\b(?:else\s+)?if\s*\(", analysis, re.IGNORECASE):
        opening = analysis.find("{", branch.end())
        if opening < 0:
            continue
        header = analysis[branch.start() : opening]
        if mismatch.search(header) is None:
            continue
        closing = _matching_brace(analysis, opening)
        if closing < 0:
            return False
        if _java_condition_is_statically_false(header):
            continue
        if not _java_mismatch_condition_is_complete(header, identity=identity, mismatch=mismatch):
            return False
        branch_body = analysis[opening + 1 : closing]
        if persistence.search(branch_body) is not None or rejection.search(branch_body) is None:
            return False
        denied = True

    return denied


def _java_condition_is_statically_false(header: str) -> bool:
    return re.search(
        r"\b(?:false|Boolean\s*\.\s*FALSE(?:\s*\.\s*booleanValue\s*\(\s*\))?)\b",
        header,
        re.IGNORECASE,
    ) is not None


def _java_mismatch_condition_is_complete(
    header: str,
    *,
    identity: str,
    mismatch: re.Pattern[str],
) -> bool:
    if "||" in header:
        return False
    remainder = mismatch.sub("", header, count=1)
    remainder = re.sub(rf"{identity}\s*!=\s*null", "", remainder, flags=re.IGNORECASE)
    remainder = re.sub(r"\b(?:else|if)\b|&&|[()\s]", "", remainder, flags=re.IGNORECASE)
    return remainder == ""


def _scan_go(text: str) -> list[_Signal]:
    signals: list[_Signal] = []
    for start, signature, body in _brace_methods(text, go_style=True):
        params = _go_parameter_names(signature)
        tainted = set(params)
        for line in body.splitlines():
            assignment = re.search(r"([A-Za-z_][\w]*)\s*:?=\s*(.+)", line)
            if assignment and (".URL.Query().Get(" in assignment.group(2) or _mentions_any(assignment.group(2), tainted)):
                tainted.add(assignment.group(1))
        for offset, line in enumerate(body.splitlines()):
            shell = re.search(
                r"exec\.Command(?:Context)?\s*\([^\n]*(?:[\"'](?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)[\"'])[^\n]*(?:[\"'](?:-c|/c|-command)[\"'])",
                line,
                re.IGNORECASE,
            )
            if shell and _mentions_any(line[shell.start() :], tainted):
                signals.append(
                    _critical(
                        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                        "Variable command text is executed through a shell",
                        "go_shell_c_variable_command",
                        start + offset,
                        "Passing variable text through sh -c, cmd /c, or PowerShell preserves command-language metacharacters.",
                        "Remove the shell and invoke a fixed executable with validated arguments.",
                    )
                )
    return signals


def _scan_php(text: str) -> list[_Signal]:
    lines = text.splitlines()
    request_vars: set[str] = set()
    cookie_vars: set[str] = set()
    signals: list[_Signal] = []
    for line_no, line in enumerate(lines, start=1):
        assignment = re.search(r"\$([A-Za-z_][\w]*)\s*=\s*(.+?);?\s*$", line)
        if assignment:
            rhs = assignment.group(2)
            if re.search(r"\$_(?:GET|POST|REQUEST)\s*\[", rhs, re.IGNORECASE) or _mentions_php(rhs, request_vars):
                request_vars.add(assignment.group(1))
            if re.search(r"\$_COOKIE\s*\[", rhs, re.IGNORECASE) or _mentions_php(rhs, cookie_vars):
                cookie_vars.add(assignment.group(1))
        comparison = re.search(r"(?:===|==|!==|!=)", line)
        if comparison and (
            (_mentions_php(line, request_vars) and _mentions_php(line, cookie_vars))
            or (re.search(r"\$_(?:GET|POST|REQUEST)", line, re.IGNORECASE) and re.search(r"\$_COOKIE", line, re.IGNORECASE))
        ):
            signals.append(
                _Signal(
                    "AUTH_CLIENT_CONTROLLED_IDENTITY_BOUNDARY",
                    "critical",
                    "high",
                    "Authorization compares two client-controlled identity values",
                    "php_cookie_request_authorization",
                    line_no,
                    "Cookies and request parameters are both caller-controlled and cannot establish object ownership.",
                    "Use the server-side authenticated session principal and compare the requested object against server-owned authorization data.",
                )
            )
    return signals


def _scan_ruby(text: str) -> list[_Signal]:
    signals: list[_Signal] = []
    lines = text.splitlines()
    lower = text.casefold()
    guarded = bool(re.search(r"current_user\s*\.|policy_scope\s*\(|authorize\s+|accessible_by\s*\(", lower, re.IGNORECASE))
    if not guarded:
        pattern = re.compile(
            r"\b[A-Z][A-Za-z0-9_:]*\.(?:find|find_by|find_by!)\s*\([^\n)]*(?:id\s*:\s*)?params\s*\[",
            re.IGNORECASE,
        )
        for line_no, line in enumerate(lines, start=1):
            if pattern.search(line):
                signals.append(
                    _Signal(
                        "API_IDOR_ROUTE_PARAM_LOOKUP",
                        "high",
                        "medium",
                        "Rails controller performs a global lookup from a route parameter",
                        "ruby_rails_global_param_lookup",
                        line_no,
                        "A global model lookup by route id can expose another user's object when no owner or policy scope is applied.",
                        "Resolve the record through current_user, policy_scope, or an equivalent tenant-scoped relation and test cross-user denial.",
                    )
                )
    block_comment = False
    heredoc_terminator: str | None = None
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if block_comment:
            if stripped == "=end":
                block_comment = False
            continue
        if stripped == "=begin":
            block_comment = True
            continue
        if heredoc_terminator is not None:
            if stripped == heredoc_terminator:
                heredoc_terminator = None
            continue
        if _ruby_upload_filename_system_call(line):
            signals.append(
                _critical(
                    "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                    "Uploaded filename reaches a one-string shell command",
                    "ruby_upload_filename_to_shell_command",
                    line_no,
                    "A client-controlled upload filename can preserve shell metacharacters when interpolated into one command string.",
                    "Avoid the shell and pass a fixed executable with separate validated arguments.",
                )
            )
        heredoc_terminator = _ruby_heredoc_terminator(line)
    return signals


def _ruby_upload_filename_system_call(line: str) -> bool:
    index = 0
    quote = ""
    escaped = False
    while index < len(line):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "#":
            return False
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if line.startswith("system", index) and _ruby_bare_call_boundary(line, index, len("system")):
            parsed = _ruby_single_double_quoted_argument(line, index + len("system"))
            if parsed is not None:
                command, closing = parsed
                if _ruby_command_has_direct_upload_filename(command):
                    return True
                index = closing + 1
                continue
        index += 1
    return False


def _ruby_bare_call_boundary(line: str, start: int, length: int) -> bool:
    before = line[start - 1] if start else ""
    after = line[start + length] if start + length < len(line) else ""
    return (
        (not before or (not (before.isalnum() or before == "_") and before not in {".", ":"}))
        and (not after or not (after.isalnum() or after == "_"))
    )


def _ruby_single_double_quoted_argument(line: str, start: int) -> tuple[str, int] | None:
    cursor = start
    while cursor < len(line) and line[cursor].isspace():
        cursor += 1
    if cursor >= len(line) or line[cursor] != "(":
        return None
    cursor += 1
    while cursor < len(line) and line[cursor].isspace():
        cursor += 1
    if cursor >= len(line) or line[cursor] != '"':
        return None
    cursor += 1
    content_start = cursor
    escaped = False
    while cursor < len(line):
        char = line[cursor]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            command = line[content_start:cursor]
            cursor += 1
            while cursor < len(line) and line[cursor].isspace():
                cursor += 1
            if cursor >= len(line) or line[cursor] != ")":
                return None
            return command, cursor
        cursor += 1
    return None


def _ruby_command_has_direct_upload_filename(command: str) -> bool:
    for match in re.finditer(r"#\{([^{}\r\n]+)\}", command):
        marker_start = match.start()
        preceding_backslashes = 0
        while marker_start > preceding_backslashes and command[marker_start - preceding_backslashes - 1] == "\\":
            preceding_backslashes += 1
        if preceding_backslashes % 2:
            continue
        expression = match.group(1).strip()
        if re.search(r"\bShellwords\s*\.\s*escape\s*\(", expression) or re.search(
            r"\.\s*shellescape\b", expression
        ):
            continue
        if re.fullmatch(
            r"[A-Za-z_]\w*(?:\s*(?:\.\s*[A-Za-z_]\w*|\[[^\[\]\r\n]+\]))*"
            r"\s*\.\s*original_filename",
            expression,
        ):
            return True
    return False


def _ruby_heredoc_terminator(line: str) -> str | None:
    code = []
    quote = ""
    escaped = False
    for char in line:
        if quote:
            code.append(" ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char == "#":
            break
        if char in {"'", '"'}:
            quote = char
            code.append(" ")
            continue
        code.append(char)
    match = re.search(r"<<[-~]?\s*([A-Za-z_]\w*)", "".join(code))
    return match.group(1) if match else None


def _brace_methods(text: str, *, go_style: bool = False) -> Iterable[tuple[int, str, str]]:
    if go_style:
        pattern = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?[A-Za-z_$][\w$]*\s*\([^)]*\)[^{]*\{", re.MULTILINE)
        matches: Iterable[re.Match[str]] = pattern.finditer(text)
    else:
        pattern = re.compile(r"\b(?:public|protected|private|internal)\s+(?!class\b|interface\b|enum\b)", re.MULTILINE)
        matches = pattern.finditer(text)
    for match in matches:
        if go_style:
            opening = text.find("{", match.start(), match.end())
        else:
            limit = min(len(text), match.start() + 1600)
            opening = text.find("{", match.start(), limit)
            semicolon = text.find(";", match.start(), limit)
            signature_candidate = text[match.start() : opening] if opening >= 0 else ""
            if opening < 0 or "(" not in signature_candidate or (semicolon >= 0 and semicolon < opening):
                continue
        closing = _matching_brace(text, opening)
        if closing < 0:
            continue
        start_line = text.count("\n", 0, opening) + 1
        yield start_line, text[match.start() : opening + 1], text[opening + 1 : closing]


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote == '\"\"\"':
            if text.startswith(quote, index):
                quote = ""
                index += 2
        elif escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif text.startswith('\"\"\"', index):
            quote = '\"\"\"'
            index += 2
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _go_parameter_names(signature: str) -> set[str]:
    match = re.search(r"\(([^)]*)\)", signature)
    if not match:
        return set()
    names: set[str] = set()
    for part in match.group(1).split(","):
        candidate = part.strip().split()[0] if part.strip() else ""
        if re.fullmatch(r"[A-Za-z_][\w]*", candidate) and candidate not in {"ctx", "context"}:
            names.add(candidate)
    return names


def _method_name_and_params(signature: str) -> tuple[str, set[str]]:
    cleaned = re.sub(r"@[A-Za-z_$][\w$.]*(?:\s*\([^)]*\))?", "", signature)
    match = re.search(r"\b([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", cleaned)
    if not match:
        return "", set()
    params: set[str] = set()
    for raw in match.group(2).split(","):
        identifiers = IDENT.findall(raw)
        if identifiers:
            params.add(identifiers[-1])
    return match.group(1), params


def _is_java_sql_sink(line: str) -> bool:
    if re.search(r"\b(?:executeQuery|executeUpdate|prepareStatement)\s*\(", line):
        return True
    return re.search(
        r"\b(?:statement|stmt|connection|jdbcTemplate|entityManager|cursor)\s*\.\s*execute\s*\(",
        line,
        re.IGNORECASE,
    ) is not None


def _java_html_response_objects(lines: list[str], response_objects: set[str]) -> set[str]:
    """Keep the first Java XSS observer to explicit servlet HTML responses only."""

    return {
        response
        for response in response_objects
        if any(
            re.search(
                rf"\b{re.escape(response)}\s*\.\s*setContentType\s*\(\s*[\"'][^\"']*text/html",
                line,
                re.IGNORECASE,
            )
            for line in lines
        )
    }


def _java_servlet_request_source(expression: str, request_objects: set[str]) -> bool:
    return any(
        re.search(
            rf"\b{re.escape(request)}\s*\.\s*get(?:Parameter|ParameterMap|Header|Headers)\s*\(",
            expression,
            re.IGNORECASE,
        )
        is not None
        for request in request_objects
    )


def _java_direct_html_encoder(
    expression: str,
    *,
    request_objects: set[str],
    tainted: set[str],
) -> bool:
    """Accept only a known direct HTML encoder around one already-tainted local value."""

    argument = _java_known_html_encoder_argument(expression)
    return argument is not None and _java_expression_is_tainted(argument, request_objects, tainted)


def _java_known_html_encoder_argument(expression: str) -> str | None:
    match = re.fullmatch(
        r"\s*(?P<callee>.+)\(\s*(?P<argument>[A-Za-z_$][\w$]*)\s*\)\s*;?\s*",
        expression,
    )
    if match is None or not _java_known_html_encoder_callee(match.group("callee")):
        return None
    return match.group("argument")


def _java_known_html_encoder_callee(value: str) -> bool:
    callee = re.sub(r"\s+", "", value).casefold()
    return any(
        re.search(pattern, callee) is not None
        for pattern in (
            r"(?:^|\.)htmlutils\.htmlescape$",
            r"(?:^|\.)esapi\.encoder\(\)\.encodeforhtml$",
            r"(?:^|\.)encode\.forhtml$",
            r"(?:^|\.)stringescapeutils\.escapehtml4$",
            r"(?:^|\.)htmlescapers\.htmlescaper\(\)\.escape$",
        )
    )


def _java_known_html_encoder_helpers(
    methods: Iterable[tuple[int, str, str]],
) -> dict[str, tuple[int, int]]:
    """Summarize only one trivial same-file helper that returns a known direct HTML encoder."""

    summaries: dict[str, tuple[int, int]] = {}
    ambiguous: set[str] = set()
    for _start, signature, body in methods:
        helper_name, _params = _method_name_and_params(signature)
        parameters = _java_method_parameter_names(signature)
        if not helper_name or not parameters or helper_name in ambiguous:
            continue
        analysis = "\n".join(_strip_c_style_comments(body.splitlines()))
        if re.search(r"\b(?:if|switch|for|while|do|try|catch|finally)\b", analysis):
            continue
        returns = re.findall(r"\breturn\s+([A-Za-z_$][\w$]*)\s*;", analysis)
        if len(returns) != 1:
            continue
        returned = returns[0]
        assignment_matches = [
            match
            for match in re.finditer(
                r"\b(?:[\w<>?,.\[\]]+\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$",
                analysis,
                re.MULTILINE,
            )
            if match.group(1) == returned
        ]
        if len(assignment_matches) != 1:
            continue
        argument = _java_known_html_encoder_argument(assignment_matches[0].group(2))
        if argument is None or argument not in parameters:
            continue
        summary = (parameters.index(argument), len(parameters))
        if helper_name in summaries:
            summaries.pop(helper_name, None)
            ambiguous.add(helper_name)
        else:
            summaries[helper_name] = summary
    return summaries


def _java_method_parameter_names(signature: str) -> list[str]:
    cleaned = re.sub(r"@[A-Za-z_$][\w$.]*(?:\s*\([^)]*\))?", "", signature)
    match = re.search(r"\b[A-Za-z_$][\w$]*\s*\(([^)]*)\)", cleaned)
    if match is None:
        return []
    names: list[str] = []
    for raw in match.group(1).split(","):
        identifiers = IDENT.findall(raw)
        if not identifiers:
            return []
        names.append(identifiers[-1])
    return names


def _java_known_html_encoder_helper_call(
    expression: str,
    *,
    helpers: dict[str, tuple[int, int]],
    request_objects: set[str],
    tainted: set[str],
) -> bool:
    if not helpers:
        return False
    match = re.fullmatch(
        r"\s*(?:(?:new\s+[A-Za-z_$][\w$<>?,.]*\s*\(\s*\)\s*\.\s*)|"
        r"(?:(?:[A-Za-z_$][\w$]*\s*\.\s*)+))?(?P<name>[A-Za-z_$][\w$]*)"
        r"\s*\((?P<arguments>.*)\)\s*;?\s*",
        expression,
    )
    if match is None:
        return False
    summary = helpers.get(match.group("name"))
    if summary is None:
        return False
    argument_index, parameter_count = summary
    arguments = _split_java_arguments(match.group("arguments"))
    if len(arguments) != parameter_count or argument_index >= len(arguments):
        return False
    # H4C deliberately accepts a local tainted value only; a nested source expression stays
    # unmodeled rather than widening the helper summary.
    return _mentions_any(_strip_string_literals(arguments[argument_index]), tainted)


def _java_record_static_value(line: str, values: dict[str, int | bool]) -> None:
    assignment = re.search(
        r"\b(?:(?:final\s+)?(?:byte|short|int|long|boolean)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$",
        line,
    )
    if assignment is None:
        return
    name, expression = assignment.group(1), assignment.group(2)
    if not re.search(r"\b(?:byte|short|int|long|boolean)\s+" + re.escape(name) + r"\b", line):
        values.pop(name, None)
        return
    value = _java_static_expression_value(expression, values)
    if type(value) in {int, bool}:
        values[name] = value
    else:
        values.pop(name, None)


def _java_constant_ternary_selected_expression(
    expression: str,
    static_values: dict[str, int | bool],
) -> str | None:
    match = re.fullmatch(
        r"\s*(?P<condition>[^?]+?)\?\s*(?P<when_true>[^:]+?)\s*:\s*(?P<when_false>.+?)\s*;?\s*",
        expression,
    )
    if match is None:
        return None
    condition = _java_static_expression_value(match.group("condition"), static_values)
    if type(condition) is not bool:
        return None
    selected = match.group("when_true") if condition else match.group("when_false")
    return selected.strip() if _java_string_literal(selected) else None


def _java_string_literal(value: str) -> bool:
    return re.fullmatch(r'\s*"(?:\\.|[^"\\])*"\s*', value) is not None


def _java_static_expression_value(
    expression: str,
    static_values: dict[str, int | bool],
) -> int | bool | None:
    candidate = expression.strip().rstrip(";").strip()
    if not candidate or re.search(r"[^A-Za-z0-9_\s()+\-*/%<>=!&|.]", candidate):
        return None
    candidate = re.sub(r"\btrue\b", "True", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\bfalse\b", "False", candidate, flags=re.IGNORECASE)
    candidate = candidate.replace("&&", " and ").replace("||", " or ")
    try:
        parsed = ast.parse(candidate, mode="eval")
    except SyntaxError:
        return None
    return _java_static_ast_value(parsed.body, static_values)


def _java_static_ast_value(node: ast.AST, static_values: dict[str, int | bool]) -> int | bool | None:
    if isinstance(node, ast.Constant) and type(node.value) in {int, bool}:
        return node.value
    if isinstance(node, ast.Name):
        return static_values.get(node.id)
    if isinstance(node, ast.UnaryOp):
        value = _java_static_ast_value(node.operand, static_values)
        if type(value) is not int:
            return None
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.USub):
            return -value
        return None
    if isinstance(node, ast.BinOp):
        left = _java_static_ast_value(node.left, static_values)
        right = _java_static_ast_value(node.right, static_values)
        if type(left) is not int or type(right) is not int:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Mod) and right != 0:
            return left % right
        return None
    if isinstance(node, ast.Compare):
        left = _java_static_ast_value(node.left, static_values)
        if left is None:
            return None
        for operator, comparator in zip(node.ops, node.comparators):
            right = _java_static_ast_value(comparator, static_values)
            if right is None or not _java_static_compare(left, operator, right):
                return False if right is not None else None
            left = right
        return True
    if isinstance(node, ast.BoolOp):
        values = [_java_static_ast_value(value, static_values) for value in node.values]
        if any(type(value) is not bool for value in values):
            return None
        return all(values) if isinstance(node.op, ast.And) else any(values) if isinstance(node.op, ast.Or) else None
    return None


def _java_static_compare(left: int | bool, operator: ast.cmpop, right: int | bool) -> bool:
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    return False


def _java_constant_ternary_safe_helpers(
    methods: Iterable[tuple[int, str, str]],
) -> dict[str, int]:
    """Summarize one same-file helper that always returns a literal branch of a static ternary."""

    summaries: dict[str, int] = {}
    ambiguous: set[str] = set()
    for _start, signature, body in methods:
        helper_name, _params = _method_name_and_params(signature)
        parameters = _java_method_parameter_names(signature)
        if not helper_name or not parameters or helper_name in ambiguous:
            continue
        lines = _strip_c_style_comments(body.splitlines())
        analysis = "\n".join(lines)
        if re.search(r"\b(?:if|switch|for|while|do|try|catch|finally)\b", analysis):
            continue
        returns = re.findall(r"\breturn\s+([A-Za-z_$][\w$]*)\s*;", analysis)
        if len(returns) != 1:
            continue
        returned = returns[0]
        static_values: dict[str, int | bool] = {}
        matched = False
        for line in lines:
            _java_record_static_value(line, static_values)
            assignment = re.search(r"\b(?:[\w<>?,.\[\]]+\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$", line)
            if assignment is None or assignment.group(1) != returned:
                continue
            if _java_constant_ternary_selected_expression(assignment.group(2), static_values) is not None:
                matched = True
        if not matched:
            continue
        if helper_name in summaries:
            summaries.pop(helper_name, None)
            ambiguous.add(helper_name)
        else:
            summaries[helper_name] = len(parameters)
    return summaries


def _java_constant_ternary_safe_helper_call(
    expression: str,
    *,
    helpers: dict[str, int],
    tainted: set[str],
) -> bool:
    if not helpers:
        return False
    match = re.fullmatch(
        r"\s*(?:(?:new\s+[A-Za-z_$][\w$<>?,.]*\s*\(\s*\)\s*\.\s*)|"
        r"(?:(?:[A-Za-z_$][\w$]*\s*\.\s*)+))?(?P<name>[A-Za-z_$][\w$]*)"
        r"\s*\((?P<arguments>.*)\)\s*;?\s*",
        expression,
    )
    if match is None:
        return False
    parameter_count = helpers.get(match.group("name"))
    if parameter_count is None:
        return False
    arguments = _split_java_arguments(match.group("arguments"))
    return len(arguments) == parameter_count and any(
        _mentions_any(_strip_string_literals(argument), tainted) for argument in arguments
    )


def _java_static_switch_safe_helpers(
    methods: Iterable[tuple[int, str, str]],
) -> dict[str, int]:
    """Summarize one same-file helper whose closed char switch selects a literal result."""

    summaries: dict[str, int] = {}
    ambiguous: set[str] = set()
    for _start, signature, body in methods:
        helper_name, _params = _method_name_and_params(signature)
        parameters = _java_method_parameter_names(signature)
        if not helper_name or not parameters or helper_name in ambiguous:
            continue
        lines = _strip_c_style_comments(body.splitlines())
        analysis = "\n".join(lines)
        if re.search(r"\b(?:if|for|while|do|try|catch|finally)\b", analysis):
            continue
        switch_matches = list(
            re.finditer(
                r"\bswitch\s*\(\s*(?P<selector>[A-Za-z_$][\w$]*)\s*\)\s*"
                r"\{(?P<cases>[^{}]*)\}",
                analysis,
                re.DOTALL,
            )
        )
        if len(switch_matches) != 1:
            continue
        returned = re.findall(r"\breturn\s+([A-Za-z_$][\w$]*)\s*;", analysis)
        if len(returned) != 1:
            continue
        switch_match = switch_matches[0]
        selector_values = _java_static_switch_selector_values(analysis[: switch_match.start()].splitlines())
        selected = selector_values.get(switch_match.group("selector"))
        if selected is None:
            continue
        if not _java_static_switch_selected_branch_returns_literal(
            switch_match.group("cases"),
            selector=selected,
            returned=returned[0],
        ):
            continue
        if helper_name in summaries:
            summaries.pop(helper_name, None)
            ambiguous.add(helper_name)
        else:
            summaries[helper_name] = len(parameters)
    return summaries


def _java_static_switch_selector_values(lines: Iterable[str]) -> dict[str, str]:
    """Track only direct ASCII String/char literals and `literal.charAt(index)` assignments."""

    values: dict[str, str] = {}
    for line in lines:
        declaration = re.search(
            r"\b(?:(?:final\s+)?(?P<type>String|char)\s+)"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expression>.+?);\s*$",
            line,
        )
        if declaration is None:
            assignment = re.search(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*=", line)
            if assignment is not None:
                values.pop(assignment.group("name"), None)
            continue
        name = declaration.group("name")
        expression = declaration.group("expression")
        if declaration.group("type") == "String":
            literal = _java_ascii_string_literal_value(expression)
            if literal is None:
                values.pop(name, None)
            else:
                values[name] = literal
            continue
        char_value = _java_static_char_value(expression, values)
        if char_value is None:
            values.pop(name, None)
        else:
            values[name] = char_value
    return values


def _java_ascii_string_literal_value(expression: str) -> str | None:
    match = re.fullmatch(r'\s*"(?P<value>[^"\\\\]*)"\s*', expression)
    return match.group("value") if match is not None else None


def _java_static_char_value(expression: str, values: dict[str, str]) -> str | None:
    literal = re.fullmatch(r"\s*'(?P<value>[^'\\\\])'\s*", expression)
    if literal is not None:
        return literal.group("value")
    char_at = re.fullmatch(
        r"\s*(?P<name>[A-Za-z_$][\w$]*)\s*\.\s*charAt\s*\(\s*(?P<index>[0-9]+)\s*\)\s*",
        expression,
    )
    if char_at is None:
        return None
    source = values.get(char_at.group("name"))
    index = int(char_at.group("index"))
    if source is None or index >= len(source):
        return None
    return source[index]


def _java_static_switch_selected_branch_returns_literal(
    cases: str,
    *,
    selector: str,
    returned: str,
) -> bool:
    labels = list(
        re.finditer(
            r"(?m)^\s*(?:case\s*'(?P<label>[^'\\\\])'|default)\s*:\s*",
            cases,
        )
    )
    selected_index = next(
        (index for index, label in enumerate(labels) if label.group("label") == selector),
        None,
    )
    if selected_index is None:
        return False
    start = labels[selected_index].end()
    end = labels[selected_index + 1].start() if selected_index + 1 < len(labels) else len(cases)
    branch = cases[start:end]
    assignments = re.findall(
        rf"\b{re.escape(returned)}\s*=\s*(.+?)\s*;",
        branch,
    )
    return (
        len(assignments) == 1
        and _java_string_literal(assignments[0])
        and re.search(r"\bbreak\s*;", branch) is not None
    )


def _java_static_switch_safe_helper_call(
    expression: str,
    *,
    helpers: dict[str, int],
    tainted: set[str],
) -> bool:
    """Use the existing bounded call matcher for a helper proven input-independent."""

    return _java_constant_ternary_safe_helper_call(expression, helpers=helpers, tainted=tainted)


def _java_static_if_safe_helpers(
    methods: Iterable[tuple[int, str, str]],
) -> dict[str, int]:
    """Summarize one same-file helper whose closed numeric if branch returns a literal."""

    summaries: dict[str, int] = {}
    ambiguous: set[str] = set()
    for _start, signature, body in methods:
        helper_name, _params = _method_name_and_params(signature)
        parameters = _java_method_parameter_names(signature)
        if not helper_name or not parameters or helper_name in ambiguous:
            continue
        lines = _strip_c_style_comments(body.splitlines())
        analysis = "\n".join(lines)
        if re.search(r"\b(?:switch|for|while|do|try|catch|finally)\b", analysis):
            continue
        if len(re.findall(r"\bif\b", analysis)) != 1 or len(re.findall(r"\belse\b", analysis)) != 1:
            continue
        returned = re.findall(r"\breturn\s+([A-Za-z_$][\w$]*)\s*;", analysis)
        if len(returned) != 1:
            continue
        if len(re.findall(rf"\b{re.escape(returned[0])}\s*=", analysis)) != 2:
            continue
        if_start = re.search(r"\bif\s*\(", analysis)
        if if_start is None:
            continue
        condition_open = analysis.find("(", if_start.start())
        condition = _java_parenthesized_expression(analysis, condition_open)
        if condition is None:
            continue
        expression, condition_end = condition
        static_values: dict[str, int | bool] = {}
        for line in analysis[: if_start.start()].splitlines():
            _java_record_static_value(line, static_values)
        selected = _java_static_expression_value(expression, static_values)
        if type(selected) is not bool:
            continue
        branches = re.match(
            rf"\s*{re.escape(returned[0])}\s*=\s*(?P<when_true>[^;{{}}]+);\s*"
            rf"else\s*{re.escape(returned[0])}\s*=\s*(?P<when_false>[^;{{}}]+);\s*"
            rf"return\s+{re.escape(returned[0])}\s*;\s*$",
            analysis[condition_end:],
            re.DOTALL,
        )
        if branches is None:
            continue
        branch = branches.group("when_true") if selected else branches.group("when_false")
        if not _java_string_literal(branch):
            continue
        if helper_name in summaries:
            summaries.pop(helper_name, None)
            ambiguous.add(helper_name)
        else:
            summaries[helper_name] = len(parameters)
    return summaries


def _java_parenthesized_expression(value: str, opening_index: int) -> tuple[str, int] | None:
    """Return one balanced parenthesized expression without accepting quoted or escaped syntax."""

    if opening_index < 0 or opening_index >= len(value) or value[opening_index] != "(":
        return None
    depth = 0
    for index in range(opening_index, len(value)):
        character = value[index]
        if character in {'"', "'", "\\"}:
            return None
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return value[opening_index + 1 : index], index + 1
            if depth < 0:
                return None
    return None


def _java_static_if_safe_helper_call(
    expression: str,
    *,
    helpers: dict[str, int],
    tainted: set[str],
) -> bool:
    """Use the existing bounded call matcher for a helper proven input-independent."""

    return _java_constant_ternary_safe_helper_call(expression, helpers=helpers, tainted=tainted)


def _java_servlet_html_sink_is_tainted(
    line: str,
    *,
    response_objects: set[str],
    request_objects: set[str],
    tainted: set[str],
) -> bool:
    """Recognize direct servlet writer output without modeling writer aliases or templates."""

    for response in response_objects:
        match = re.search(
            rf"\b{re.escape(response)}\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*"
            r"(format|printf|print|println|write)\s*\(",
            line,
            re.IGNORECASE,
        )
        if match is None:
            continue
        arguments = _java_arguments_after_opening(line, match.end() - 1)
        if not arguments:
            continue
        method = match.group(1).casefold()
        if method in {"format", "printf"}:
            format_index = 1 if _java_locale_argument(arguments[0]) else 0
            if format_index >= len(arguments):
                continue
            format_argument = arguments[format_index]
            if _java_expression_is_tainted(format_argument, request_objects, tainted):
                return True
            if _java_literal_format_has_conversion(format_argument) and any(
                _java_expression_is_tainted(argument, request_objects, tainted)
                for argument in arguments[format_index + 1 :]
            ):
                return True
            continue
        if any(_java_expression_is_tainted(argument, request_objects, tainted) for argument in arguments):
            return True
    return False


def _java_expression_is_tainted(
    expression: str,
    request_objects: set[str],
    tainted: set[str],
) -> bool:
    return _java_servlet_request_source(expression, request_objects) or _mentions_any(
        _strip_string_literals(expression), tainted
    )


def _java_arguments_after_opening(line: str, opening: int) -> list[str]:
    if opening < 0 or opening >= len(line) or line[opening] != "(":
        return []
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, len(line)):
        char = line[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '\"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return _split_java_arguments(line[opening + 1 : index])
    return []


def _split_java_arguments(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '\"'}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return result


def _java_locale_argument(argument: str) -> bool:
    return re.fullmatch(
        r"(?:java\s*\.\s*util\s*\.\s*)?Locale(?:\s*\.\s*[A-Za-z_$][\w$]*)?",
        argument.strip(),
    ) is not None


def _java_literal_format_has_conversion(argument: str) -> bool:
    literal = re.fullmatch(r'\s*"((?:\\.|[^"\\])*)"\s*', argument)
    if literal is None:
        return False
    return re.search(
        r"(?<!%)%(?:\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?(?:[tT])?[A-Za-z]",
        literal.group(1),
    ) is not None


def _mentions_any(text: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _scope_mentions_any(
    text: str,
    scope_id: int,
    tainted: dict[int, set[str]],
    bindings: dict[int, set[str]],
    parents: dict[int, int | None],
) -> bool:
    for name in IDENT.findall(text):
        current: int | None = scope_id
        while current is not None:
            if name in bindings.get(current, set()):
                if name in tainted.get(current, set()):
                    return True
                break
            current = parents.get(current)
    return False


def _mentions_php(text: str, names: set[str]) -> bool:
    return any(re.search(rf"\${re.escape(name)}\b", text) for name in names)


def _call_arguments(line: str) -> str:
    opening = line.find("(")
    return line[opening + 1 :] if opening >= 0 else line


@lru_cache(maxsize=16384)
def _strip_line_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index in range(len(line) - 1):
        char = line[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif line[index : index + 2] == "//":
            return line[:index]
    return line


def _strip_c_style_comments(lines: list[str]) -> list[str]:
    return list(_strip_c_style_comments_cached(tuple(lines)))


@lru_cache(maxsize=256)
def _strip_c_style_comments_cached(lines: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    in_block = False
    for line in lines:
        output: list[str] = []
        quote = ""
        escaped = False
        index = 0
        while index < len(line):
            if in_block:
                closing = line.find("*/", index)
                if closing < 0:
                    index = len(line)
                    continue
                in_block = False
                index = closing + 2
                continue
            char = line[index]
            if escaped:
                output.append(char)
                escaped = False
            elif char == "\\":
                output.append(char)
                escaped = True
            elif quote:
                output.append(char)
                if char == quote:
                    quote = ""
            elif char in {"'", '"', "`"}:
                output.append(char)
                quote = char
            elif line.startswith("/*", index):
                in_block = True
                index += 2
                continue
            elif line.startswith("//", index):
                break
            else:
                output.append(char)
            index += 1
        result.append("".join(output))
    return tuple(result)


@lru_cache(maxsize=16384)
def _strip_string_literals(text: str) -> str:
    output: list[str] = []
    quote = ""
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            output.append(" ")
        elif char == "\\":
            escaped = True
            output.append(" ")
        elif quote:
            if char == quote:
                quote = ""
            output.append(" ")
        elif char in {"'", '"', "`"}:
            quote = char
            output.append(" ")
        else:
            output.append(char)
    return "".join(output)


def _first_relative_line(lines: list[str], names: tuple[str, ...]) -> int:
    for index, line in enumerate(lines):
        if _mentions_any(line, set(names)):
            return index
    return 0


def _critical(rule_id: str, title: str, subtype: str, line: int, why: str, recommendation: str) -> _Signal:
    return _Signal(rule_id, "critical", "high", title, subtype, line, why, recommendation)
