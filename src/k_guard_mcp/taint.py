from __future__ import annotations

import ast
import heapq
import re
import string
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import evidence_hash
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding, FlowEdge, FlowMap, FlowNode


SENSITIVE_NAME = re.compile(
    r"(email|phone|name|address|rrn|frn|passport|license|ci|di|birth|patient|medical|"
    r"account|card|token|secret|password|api[_-]?key|user|customer|profile|"
    r"주민|전화|이메일|주소|이름|환자|진료|계좌|카드)",
    re.IGNORECASE,
)
JS_TS_SUFFIXES = {
    ".cjs",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".svelte",
    ".ts",
    ".tsx",
    ".vue",
}
JS_TS_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
JS_TS_SINK_HINTS = (
    "console.",
    "logger.",
    "fetch(",
    "axios.",
    "ky(",
    "got(",
    "openai",
    "anthropic",
    "gemini",
    "chat.completions",
    "responses.create",
    "generatecontent",
    "calltool",
    "call_tool",
    "usemcptool",
    "use_mcp_tool",
    "clientsession",
    "response.json",
    "nextresponse.json",
    "res.json",
    "reply.send",
    ".create(",
    ".update(",
    ".insert(",
    ".upsert(",
    ".save(",
    "exec(",
    "execsync(",
    "spawn(",
    "spawnsync(",
    ".query(",
    ".execute(",
)
JS_TS_COMMAND_METHODS = frozenset({"exec", "execSync", "spawn", "spawnSync"})
JS_TS_PROCESS_METHODS = frozenset(
    {*JS_TS_COMMAND_METHODS, "execFile", "execFileSync"}
)
_JS_TS_COMMAND_MODULE_LITERAL = (
    r"['\"](?:node:)?child_process['\"]|['\"]shelljs['\"]|['\"]@actions/exec['\"]"
)
DEFAULT_JS_TS_EDGES_PER_FILE = 32
DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE = 32

PYTHON_LOG_LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "warn": 30,
    "error": 40,
    "exception": 40,
    "critical": 50,
}
PYTHON_LOG_LEVEL_NAMES = {10: "DEBUG", 20: "INFO", 30: "WARNING", 40: "ERROR", 50: "CRITICAL"}
PYTHON_LOG_ENTRYPOINT_NAMES = {"__main__.py", "app.py", "asgi.py", "main.py", "manage.py", "server.py", "wsgi.py"}


@dataclass(frozen=True)
class TaintSource:
    kind: str
    name: str
    line: int
    line_hash: str
    sensitive: bool
    projection: str = "raw"


@dataclass(frozen=True)
class JsTsFunctionSummary:
    name: str
    file: str
    line: int
    line_hash: str
    risk: str
    data_access: str
    param_names: tuple[str, ...]


@dataclass(frozen=True)
class _JsTsBindingScope:
    start: int
    end: int
    depth: int

    def contains(self, position: int) -> bool:
        return self.start <= position <= self.end


@dataclass(frozen=True)
class _JsTsBindingEvent:
    name: str
    scope: _JsTsBindingScope
    activation: int
    order: int
    is_command: bool


@dataclass(frozen=True)
class _JsTsBindingTimeline:
    scope: _JsTsBindingScope
    activations: tuple[int, ...]
    command_states: tuple[bool, ...]


@dataclass(frozen=True)
class JsTsCommandBindings:
    namespaces: frozenset[str] = frozenset()
    line_starts: tuple[int, ...] = ()
    source_length: int = 0
    events: tuple[_JsTsBindingEvent, ...] = ()
    event_index: dict[str, tuple[_JsTsBindingEvent, ...]] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )
    timeline_index: dict[str, tuple[_JsTsBindingTimeline, ...]] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )
    position_index: dict[tuple[str, int], bool] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )

    def _position(self, line_no: int | None, column: int | None = None) -> int:
        if line_no is None or not self.line_starts:
            return self.source_length
        index = min(max(line_no - 1, 0), len(self.line_starts) - 1)
        return min(
            self.source_length,
            self.line_starts[index] + max(0, int(column or 0)),
        )

    def is_command(
        self,
        name: str,
        line_no: int | None,
        column: int | None = None,
    ) -> bool:
        position = self._position(line_no, column)
        position_key = (name, position)
        if column is not None and position_key in self.position_index:
            return self.position_index[position_key]
        timelines = self.timeline_index.get(name, ())
        applicable_timelines = [
            timeline
            for timeline in timelines
            if timeline.activations
            and timeline.activations[0] <= position
            and timeline.scope.contains(position)
        ]
        if applicable_timelines:
            timeline = max(
                applicable_timelines,
                key=lambda item: (
                    item.scope.depth,
                    item.scope.start,
                    -item.scope.end,
                ),
            )
            index = bisect_right(timeline.activations, position) - 1
            return (
                index >= 0
                and timeline.command_states[index]
            )

        name_events = self.event_index.get(name)
        if name_events is None:
            name_events = tuple(
                event for event in self.events if event.name == name
            )
        applicable = [
            event
            for event in name_events
            if event.scope.contains(position)
            and event.activation <= position
        ]
        if not applicable:
            return False
        winning_scope = max(
            (event.scope for event in applicable),
            key=lambda scope: (scope.depth, scope.start, -scope.end),
        )
        return max(
            (event for event in applicable if event.scope == winning_scope),
            key=lambda event: (event.activation, event.order),
        ).is_command

    def at_line(self, line_no: int | None) -> frozenset[str]:
        return frozenset(
            name
            for name in self.namespaces
            if self.is_command(name, line_no)
        )


@dataclass(frozen=True)
class JsTsHandlerScope:
    kind: str
    rendered: str
    line: int


@dataclass(frozen=True)
class JsTsExpressRoute:
    method: str
    path: str
    middleware: tuple[str, ...]
    body: str
    line: int


@dataclass(frozen=True)
class PythonSecurityValue:
    tainted: bool = False
    source_line: int = 0
    constant: Any = None
    constant_known: bool = False
    sanitized_for: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PythonFunctionSummary:
    name: str
    return_kind: str
    constant: Any = None
    html_sanitizer_dependencies: frozenset[str] = frozenset()
    source_file: str = ""


@dataclass(frozen=True)
class _PythonHtmlSummaryValue:
    sources: frozenset[str] = frozenset()
    unsafe_sources: frozenset[str] = frozenset()
    html_sanitizer_dependencies: frozenset[str] = frozenset()
    constant: Any = None
    constant_known: bool = False
    trusted_constant: bool = False
    invalid: bool = False


@dataclass(frozen=True)
class PythonSinkSummary:
    name: str
    file: str
    line: int
    line_hash: str
    rule_id: str
    param_names: tuple[str, ...]
    dangerous_param_indexes: tuple[int, ...]
    proven_command_primitive: str | None = None


@dataclass(frozen=True)
class PythonWeakPrefixGuardSummary:
    name: str
    file: str
    param_names: tuple[str, ...]
    guarded_param_index: int


class AstTaintAnalyzer:
    """Python AST taint plus lightweight JS/TS taint for privacy source-to-sink triage."""

    def __init__(
        self,
        id_factory: IdFactory | None = None,
        max_js_ts_edges_per_file: int = DEFAULT_JS_TS_EDGES_PER_FILE,
        max_js_ts_findings_per_rule_per_file: int = (
            DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE
        ),
    ) -> None:
        self.ids = id_factory or IdFactory()
        self.max_js_ts_edges_per_file = max_js_ts_edges_per_file
        self.max_js_ts_findings_per_rule_per_file = max_js_ts_findings_per_rule_per_file
        self.js_ts_function_summaries: dict[str, JsTsFunctionSummary] = {}
        self.js_ts_ambiguous_function_names: set[str] = set()
        self.python_function_summaries: dict[str, PythonFunctionSummary] = {}
        self.python_observed_function_names: set[str] = set()
        self.python_ambiguous_function_names: set[str] = set()
        self.python_html_sanitizer_status: dict[str, bool] = {}
        self.python_html_sanitizer_files: dict[str, str] = {}
        self.python_sink_summaries: dict[str, list[PythonSinkSummary]] = {}
        self.python_weak_prefix_guard_summaries: dict[
            str,
            list[PythonWeakPrefixGuardSummary],
        ] = {}
        self.python_root_logging_levels: dict[Path, set[int]] = {}
        self.python_logger_levels_by_file: dict[Path, dict[str, int | None]] = {}
        self.python_local_module_names: set[str] = set()

    def reset_project_summaries(self) -> None:
        self.js_ts_function_summaries = {}
        self.js_ts_ambiguous_function_names = set()
        self.python_function_summaries = {}
        self.python_observed_function_names = set()
        self.python_ambiguous_function_names = set()
        self.python_html_sanitizer_status = {}
        self.python_html_sanitizer_files = {}
        self.python_sink_summaries = {}
        self.python_weak_prefix_guard_summaries = {}
        self.python_root_logging_levels = {}
        self.python_logger_levels_by_file = {}
        self.python_local_module_names = set()

    def collect_project_file(self, path: Path, text: str) -> None:
        suffix = path.suffix.lower()
        if suffix in JS_TS_SUFFIXES:
            for summary in _collect_js_ts_function_summaries(path, _strip_js_ts_comments(text.splitlines())):
                if summary.name in self.js_ts_ambiguous_function_names:
                    continue
                previous = self.js_ts_function_summaries.get(summary.name)
                if previous is None:
                    self.js_ts_function_summaries[summary.name] = summary
                elif previous != summary:
                    self.js_ts_function_summaries.pop(summary.name, None)
                    self.js_ts_ambiguous_function_names.add(summary.name)
            return
        if suffix == ".py":
            self.python_local_module_names.add(path.stem.casefold())
            self.python_local_module_names.add(path.parent.name.casefold())
            tree, _ = _parse_python_tree_with_recovery(text)
            if tree is not None:
                resolved = path.resolve()
                sanitizer_definitions = (
                    _classify_python_html_sanitizer_definitions(tree)
                )
                self.python_logger_levels_by_file[resolved] = _collect_python_logger_levels(tree)
                if path.name.lower() in PYTHON_LOG_ENTRYPOINT_NAMES:
                    levels = _collect_python_root_logging_levels(tree)
                    if levels:
                        self.python_root_logging_levels.setdefault(resolved.parent, set()).update(levels)
                for name, verified in sanitizer_definitions:
                    normalized_name = name.lower()
                    source_file = str(resolved)
                    if normalized_name not in self.python_html_sanitizer_status:
                        self.python_html_sanitizer_status[normalized_name] = verified
                        if verified:
                            self.python_html_sanitizer_files[
                                normalized_name
                            ] = source_file
                        continue
                    if (
                        not verified
                        or self.python_html_sanitizer_files.get(
                            normalized_name
                        )
                        != source_file
                    ):
                        self.python_html_sanitizer_status[normalized_name] = False
                        self.python_html_sanitizer_files.pop(
                            normalized_name,
                            None,
                        )
                for name, summary in _classify_python_function_summaries(
                    tree,
                    sanitizer_definitions,
                ):
                    name = name.lower()
                    if summary is not None:
                        summary = PythonFunctionSummary(
                            name,
                            summary.return_kind,
                            summary.constant,
                            summary.html_sanitizer_dependencies,
                            str(resolved),
                        )
                    if name in self.python_ambiguous_function_names:
                        continue
                    if name not in self.python_observed_function_names:
                        self.python_observed_function_names.add(name)
                        if summary is not None:
                            self.python_function_summaries[name] = summary
                        continue
                    previous = self.python_function_summaries.get(name)
                    if previous != summary:
                        self.python_function_summaries.pop(name, None)
                        self.python_ambiguous_function_names.add(name)
                for summary in _collect_python_sink_summaries(tree, path, text.splitlines()):
                    self.python_sink_summaries.setdefault(summary.name, []).append(summary)
                for summary in _collect_python_weak_prefix_guard_summaries(
                    tree,
                    path,
                ):
                    self.python_weak_prefix_guard_summaries.setdefault(
                        summary.name,
                        [],
                    ).append(summary)

    def append_file(self, flow: FlowMap, path: Path, text: str) -> None:
        suffix = path.suffix.lower()
        if suffix in JS_TS_SUFFIXES:
            _JsTsTaintVisitor(
                self.ids,
                flow,
                path,
                text.splitlines(),
                max_edges=self.max_js_ts_edges_per_file,
                max_findings_per_rule=self.max_js_ts_findings_per_rule_per_file,
                function_summaries=self.js_ts_function_summaries,
            ).visit()
            return
        if suffix != ".py":
            return
        tree, recovered_lines = _parse_python_tree_with_recovery(text)
        if tree is None:
            flow.findings.append(
                Finding(
                    id=self.ids.next(),
                    source="ast-taint",
                    rule_id="PYTHON_AST_PARSE_FAILED",
                    severity="high",
                    confidence="high",
                    title="Python source could not be parsed for semantic review",
                    file=str(path),
                    evidence=f"detector_subtype=python_ast_parse_failed file_hash={evidence_hash(str(path))} raw_returned=false",
                    why_it_matters="A source file that cannot be parsed leaves request-to-sink and authorization paths unreviewed.",
                    recommendation="Run the scanner with a compatible Python parser or correct the syntax before release review.",
                    audit_depth=1,
                    inspected_scope="The file was read, but Python AST construction failed closed.",
                    not_inspected="No semantic Python flow claim is made for this file.",
                )
            )
            return
        if recovered_lines:
            flow.findings.append(
                Finding(
                    id=self.ids.next(),
                    source="ast-taint",
                    rule_id="PYTHON_AST_FSTRING_RECOVERY_USED",
                    severity="info",
                    confidence="high",
                    title="Python AST used narrow f-string syntax recovery",
                    file=str(path),
                    evidence=(
                        f"detector_subtype=python_ast_fstring_recovery recovered_line_count={len(recovered_lines)} "
                        f"line_set_hash={evidence_hash('|'.join(str(line) for line in recovered_lines))} raw_returned=false"
                    ),
                    why_it_matters="A newer f-string grammar was normalized only on syntax-error lines so the remaining file could be reviewed.",
                    recommendation="Use a scanner runtime matching the app's Python grammar for the highest-fidelity release run.",
                    audit_depth=3,
                    inspected_scope="All recoverable statements outside the invalid f-string expression remained in the AST review.",
                    not_inspected="Expression semantics inside the recovered f-string line were not preserved.",
                )
            )
        lines = text.splitlines()
        visitor = _PythonTaintVisitor(
            self.ids,
            flow,
            path,
            lines,
            default_log_threshold=self.effective_python_log_threshold(path),
            logger_thresholds=self.python_logger_levels_by_file.get(path.resolve(), {}),
        )
        visitor.visit(tree)
        function_summaries = dict(self.python_function_summaries)
        local_request_summaries = _collect_python_local_request_function_summaries(
            tree,
            path,
        )
        same_file_request_backfills = frozenset(
            name
            for name in local_request_summaries
            if name not in function_summaries
        )
        for name in same_file_request_backfills:
            function_summaries[name] = local_request_summaries[name]
        _PythonSecurityTaintAnalyzer(
            self.ids,
            flow,
            path,
            lines,
            function_summaries,
            same_file_request_backfills,
            {
                name: self.python_html_sanitizer_files[name]
                for name, verified in self.python_html_sanitizer_status.items()
                if verified and name in self.python_html_sanitizer_files
            },
            self.python_local_module_names,
            self.python_sink_summaries,
            self.python_weak_prefix_guard_summaries,
        ).analyze(tree)

    def effective_python_log_threshold(self, path: Path) -> int | None:
        """Return an unambiguous root logger threshold for the nearest app scope."""

        resolved = path.resolve()
        candidates: list[tuple[int, set[int]]] = []
        for scope, levels in self.python_root_logging_levels.items():
            if scope != resolved.parent and scope not in resolved.parents:
                continue
            candidates.append((len(scope.parts), levels))
        if not candidates:
            return None
        _, nearest = max(candidates, key=lambda candidate: candidate[0])
        return next(iter(nearest)) if len(nearest) == 1 else None

    def python_log_line_is_inactive(self, path: Path, line: str) -> bool:
        """Conservatively identify a log call disabled by a static effective level."""

        match = re.search(
            r"\b(?P<logger>logging|[A-Za-z_][A-Za-z0-9_]*)\.(?P<level>debug|info|warning|warn|error|exception|critical)\s*\(",
            line,
            re.IGNORECASE,
        )
        if match is None:
            return False
        call_level = PYTHON_LOG_LEVELS[match.group("level").lower()]
        logger_name = match.group("logger")
        local_levels = self.python_logger_levels_by_file.get(path.resolve(), {})
        if logger_name in local_levels:
            threshold = local_levels[logger_name]
            return threshold is not None and call_level < threshold
        threshold = self.effective_python_log_threshold(path)
        return threshold is not None and call_level < threshold


def _parse_python_tree_with_recovery(text: str) -> tuple[ast.AST | None, tuple[int, ...]]:
    lines = text.splitlines(keepends=True)
    recovered: list[int] = []
    for _ in range(100):
        try:
            return ast.parse("".join(lines)), tuple(recovered)
        except SyntaxError as exc:
            line_index = int(exc.lineno or 1) - 1
            if line_index < 0 or line_index >= len(lines):
                return None, tuple(recovered)
            line = lines[line_index]
            lowered = line.lower()
            has_fstring = any(marker in lowered for marker in ("f'", 'f"', "rf'", 'rf"', "fr'", 'fr"'))
            open_brace = line.find("{")
            close_brace = line.rfind("}")
            if not has_fstring or open_brace < 0 or close_brace <= open_brace:
                return None, tuple(recovered)
            replacement = line[:open_brace] + "{0}" + line[close_brace + 1 :]
            if replacement == line:
                return None, tuple(recovered)
            lines[line_index] = replacement
            recovered.append(line_index + 1)
    return None, tuple(recovered)


def _static_python_log_level(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return int(node.value)
        if isinstance(node.value, str):
            return PYTHON_LOG_LEVELS.get(node.value.lower())
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "logging":
        return PYTHON_LOG_LEVELS.get(node.attr.lower())
    return None


def _collect_python_root_logging_levels(tree: ast.AST) -> set[int]:
    levels: set[int] = set()
    for statement in getattr(tree, "body", []):
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        name = _call_name(call.func).lower()
        if name == "logging.basicconfig":
            level_node = next((keyword.value for keyword in call.keywords if keyword.arg == "level"), None)
            level = _static_python_log_level(level_node)
            if level is not None:
                levels.add(level)
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr.lower() != "setlevel" or not call.args:
            continue
        receiver = call.func.value
        if not isinstance(receiver, ast.Call) or _call_name(receiver.func).lower() != "logging.getlogger" or receiver.args:
            continue
        level = _static_python_log_level(call.args[0])
        if level is not None:
            levels.add(level)
    return levels


def _collect_python_logger_levels(tree: ast.AST) -> dict[str, int | None]:
    observed: dict[str, set[int | None]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr.lower() != "setlevel" or not isinstance(node.func.value, ast.Name):
            continue
        logger_name = node.func.value.id
        level = _static_python_log_level(node.args[0]) if node.args else None
        observed.setdefault(logger_name, set()).add(level)
    return {
        logger_name: next(iter(levels)) if len(levels) == 1 and None not in levels else None
        for logger_name, levels in observed.items()
    }


def _collect_python_function_summaries(tree: ast.AST) -> list[PythonFunctionSummary]:
    return [
        summary
        for _, summary in _classify_python_function_summaries(tree)
        if summary is not None
    ]


def _collect_python_local_request_function_summaries(
    tree: ast.AST,
    path: Path,
) -> dict[str, PythonFunctionSummary]:
    """Backfill stable same-file request helpers without overriding project summaries."""

    sanitizer_status: dict[str, bool] = {}
    for name, verified in _classify_python_html_sanitizer_definitions(tree):
        normalized_name = name.lower()
        sanitizer_status[normalized_name] = (
            sanitizer_status.get(normalized_name, True)
            and verified
        )
    verified_sanitizers = frozenset(
        name
        for name, verified in sanitizer_status.items()
        if verified
    )
    standard_sanitizer_calls = (
        _python_standard_html_sanitizer_calls_by_function(tree)
    )
    summaries: dict[str, PythonFunctionSummary] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        trusted_sanitizers = verified_sanitizers.union(
            _python_trusted_standard_html_sanitizers(
                tree,
                node,
                standard_sanitizer_calls.get(node, {}),
            )
        )
        summary = _python_function_summary(node, trusted_sanitizers)
        if (
            summary is None
            or summary.return_kind != "request"
            or not _python_definition_header_is_inert(node)
        ):
            continue
        name = node.name.lower()
        summaries[name] = PythonFunctionSummary(
            name,
            "request",
            source_file=str(path.resolve()),
        )
    return summaries


def _classify_python_html_sanitizer_definitions(
    tree: ast.AST,
) -> list[tuple[str, bool]]:
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    candidates = {
        node
        for node in functions
        if _python_function_may_be_html_encoder(node)
    }
    if not candidates:
        return [(node.name, False) for node in functions]
    module_literals = _python_stable_module_literal_bindings(tree)
    shadowed_builtins = _python_shadowed_html_encoder_builtins(tree)
    return [
        (
            node.name,
            (
                _python_function_is_verified_html_encoder(
                    node,
                    module_literals,
                    shadowed_builtins,
                )
                if (
                    node in candidates
                    and _python_top_level_function_binding_is_stable(tree, node)
                )
                else False
            ),
        )
        for node in functions
    ]


def _python_top_level_function_binding_is_stable(
    tree: ast.AST,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    body = getattr(tree, "body", [])
    definition_index = next(
        (index for index, statement in enumerate(body) if statement is node),
        None,
    )
    if (
        definition_index is None
        or not _python_definition_header_is_inert(node)
    ):
        return False
    return (
        all(
            _python_top_level_prefix_statement_is_inert(statement)
            for statement in body[:definition_index]
        )
        and all(
            _python_top_level_statement_preserves_binding(statement, node.name)
            for statement in body[definition_index + 1 :]
        )
    )


def _python_same_file_request_function_binding_is_stable(
    tree: ast.AST,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Allow unrelated initialization while preserving the helper binding."""

    body = getattr(tree, "body", [])
    definition_index = next(
        (index for index, statement in enumerate(body) if statement is node),
        None,
    )
    return (
        definition_index is not None
        and _python_definition_header_is_inert(node)
        and all(
            _python_top_level_statement_preserves_binding(statement, node.name)
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
            )
            for statement in body[definition_index + 1 :]
        )
    )


def _python_top_level_prefix_statement_is_inert(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass)):
        return True
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _python_definition_header_is_inert(statement)
    if isinstance(statement, ast.ClassDef):
        return _python_class_definition_is_inert(statement)
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ):
        return True
    targets: list[ast.AST] = []
    value: ast.AST | None = None
    if isinstance(statement, ast.Assign):
        targets = list(statement.targets)
        value = statement.value
    elif isinstance(statement, ast.AnnAssign):
        targets = [statement.target]
        value = statement.value
        if (
            statement.annotation is not None
            and not _python_definition_expression_is_inert(statement.annotation)
        ):
            return False
    if value is None or not all(isinstance(target, ast.Name) for target in targets):
        return False
    try:
        ast.literal_eval(value)
    except (TypeError, ValueError):
        return False
    return True


def _python_top_level_statement_preserves_binding(
    statement: ast.stmt,
    name: str,
) -> bool:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return (
            statement.name != name
            and _python_definition_header_is_inert(statement)
        )
    if isinstance(statement, ast.ClassDef):
        return (
            statement.name != name
            and _python_class_definition_is_inert(statement)
        )
    if isinstance(statement, ast.Pass):
        return True
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _python_class_definition_is_inert(node: ast.ClassDef) -> bool:
    return (
        not node.decorator_list
        and not node.bases
        and not node.keywords
        and all(
            _python_class_body_statement_is_inert(statement)
            for statement in node.body
        )
    )


def _python_class_body_statement_is_inert(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _python_definition_header_is_inert(statement)
    if isinstance(statement, ast.Pass):
        return True
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _python_definition_header_is_inert(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    if node.decorator_list:
        return False
    arguments = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if node.args.vararg is not None:
        arguments.append(node.args.vararg)
    if node.args.kwarg is not None:
        arguments.append(node.args.kwarg)
    expressions = [
        *node.args.defaults,
        *(default for default in node.args.kw_defaults if default is not None),
        *(argument.annotation for argument in arguments if argument.annotation is not None),
    ]
    if node.returns is not None:
        expressions.append(node.returns)
    expressions.extend(getattr(node, "type_params", []))
    return all(
        _python_definition_expression_is_inert(expression)
        for expression in expressions
    )


def _python_definition_expression_is_inert(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except (TypeError, ValueError):
        pass
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


def _python_function_may_be_html_encoder(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if (
        len(parameters) != 1
        or node.args.vararg is not None
        or node.args.kwarg is not None
    ):
        return False
    source_name = parameters[0].arg
    return any(
        isinstance(statement, ast.For)
        and isinstance(statement.target, ast.Name)
        and isinstance(statement.iter, ast.Name)
        and statement.iter.id == source_name
        for statement in node.body
    )


def _python_literal_bindings(
    statements: list[ast.stmt],
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    for statement in statements:
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            targets = list(statement.targets)
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        if value is None:
            continue
        try:
            literal = ast.literal_eval(value)
        except (TypeError, ValueError):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = literal
    return bindings


def _python_stable_module_literal_bindings(
    tree: ast.AST,
) -> dict[str, Any]:
    bindings = _python_literal_bindings(getattr(tree, "body", []))
    write_counts = {name: 0 for name in bindings}
    method_receivers: set[str] = set()
    escaped_bindings: set[str] = set()
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = [node.target]
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        for target in targets:
            for name in _python_assignment_root_names(target):
                if name in write_counts:
                    write_counts[name] += 1
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = _python_expression_root_name(node.func.value)
            if root in bindings:
                method_receivers.add(root)
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in bindings
        ):
            parent = parents.get(node)
            safe_read = (
                isinstance(parent, ast.Subscript)
                and parent.value is node
            ) or (
                isinstance(parent, ast.Compare)
                and node in parent.comparators
            )
            if not safe_read:
                escaped_bindings.add(node.id)
    return {
        name: value
        for name, value in bindings.items()
        if (
            write_counts[name] == 1
            and name not in method_receivers
            and name not in escaped_bindings
        )
    }


def _python_shadowed_html_encoder_builtins(
    tree: ast.AST,
) -> frozenset[str]:
    protected = {"hex", "ord"}
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if node.id in protected:
                shadowed.add(node.id)
        elif isinstance(node, ast.arg) and node.arg in protected:
            shadowed.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in protected:
                shadowed.add(node.name)
        elif isinstance(node, ast.alias):
            bound_name = node.asname or node.name.split(".", 1)[0]
            if node.name == "*":
                shadowed.update(protected)
            elif bound_name in protected:
                shadowed.add(bound_name)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Store)
            and node.attr in protected
            and _python_expression_root_name(node.value) == "builtins"
        ):
            shadowed.add(node.attr)
    return frozenset(shadowed)


def _python_assignment_root_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        root = _python_expression_root_name(node.value)
        return [root] if root is not None else []
    if isinstance(node, (ast.Tuple, ast.List)):
        return [
            name
            for item in node.elts
            for name in _python_assignment_root_names(item)
        ]
    return []


def _python_expression_root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _python_function_is_verified_html_encoder(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_literals: dict[str, Any],
    shadowed_builtins: frozenset[str],
) -> bool:
    """Prove one bounded character encoder; every unmodelled construct rejects."""

    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if (
        len(parameters) != 1
        or node.args.vararg is not None
        or node.args.kwarg is not None
        or not _python_encoder_signature_is_inert(node)
        or shadowed_builtins
    ):
        return False
    source_name = parameters[0].arg
    literals = dict(module_literals)
    literals.update(_python_literal_bindings(node.body))
    accumulators: set[str] = set()
    return_names: set[str] = set()
    source_loop_count = 0
    for statement in node.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if value is None:
                continue
            try:
                literal = ast.literal_eval(value)
            except (TypeError, ValueError):
                return False
            for target in targets:
                if not isinstance(target, ast.Name):
                    return False
                literals[target.id] = literal
                if isinstance(literal, str):
                    if not _python_html_encoder_constant_is_safe(literal):
                        return False
                    accumulators.add(target.id)
            continue
        if isinstance(statement, ast.For):
            if (
                not isinstance(statement.target, ast.Name)
                or not isinstance(statement.iter, ast.Name)
                or statement.iter.id != source_name
                or statement.orelse
            ):
                return False
            source_loop_count += 1
            if not _python_html_encoder_block_is_safe(
                statement.body,
                statement.target.id,
                accumulators,
                literals,
            ):
                return False
            continue
        if isinstance(statement, ast.Return):
            if not isinstance(statement.value, ast.Name):
                return False
            return_names.add(statement.value.id)
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass)):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        return False
    return (
        source_loop_count == 1
        and len(return_names) == 1
        and return_names.issubset(accumulators)
    )


def _python_encoder_signature_is_inert(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    if (
        node.decorator_list
        or node.args.defaults
        or any(default is not None for default in node.args.kw_defaults)
        or getattr(node, "type_params", [])
    ):
        return False
    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    annotations = [
        parameter.annotation
        for parameter in parameters
        if parameter.annotation is not None
    ]
    if node.returns is not None:
        annotations.append(node.returns)
    return all(
        isinstance(annotation, (ast.Name, ast.Constant))
        for annotation in annotations
    )


def _python_html_encoder_block_is_safe(
    statements: list[ast.stmt],
    character_name: str,
    accumulators: set[str],
    literals: dict[str, Any],
    raw_character_is_safe: bool = False,
) -> bool:
    for statement in statements:
        if isinstance(statement, ast.If):
            guarded_safe = (
                raw_character_is_safe
                or _python_condition_guarantees_html_safe_character(
                    statement.test,
                    character_name,
                    literals,
                )
            )
            if not _python_html_encoder_block_is_safe(
                statement.body,
                character_name,
                accumulators,
                literals,
                guarded_safe,
            ):
                return False
            if not _python_html_encoder_block_is_safe(
                statement.orelse,
                character_name,
                accumulators,
                literals,
                raw_character_is_safe,
            ):
                return False
            continue
        if isinstance(statement, ast.AugAssign):
            if (
                not isinstance(statement.target, ast.Name)
                or statement.target.id not in accumulators
                or not isinstance(statement.op, ast.Add)
                or not _python_html_encoder_output_is_safe(
                    statement.value,
                    character_name,
                    literals,
                    raw_character_is_safe,
                )
            ):
                return False
            continue
        if isinstance(statement, (ast.Pass, ast.Continue)):
            continue
        return False
    return True


def _python_condition_guarantees_html_safe_character(
    node: ast.AST,
    character_name: str,
    literals: dict[str, Any],
) -> bool:
    if isinstance(node, ast.BoolOp):
        checks = [
            _python_condition_guarantees_html_safe_character(
                value,
                character_name,
                literals,
            )
            for value in node.values
        ]
        return all(checks) if isinstance(node.op, ast.Or) else any(checks)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"isalnum", "isalpha", "isdecimal", "isdigit"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == character_name
        and not node.args
        and not node.keywords
    ):
        return True
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.left, ast.Name)
        and node.left.id == character_name
    ):
        comparator = node.comparators[0]
        allowlist = (
            literals.get(comparator.id)
            if isinstance(comparator, ast.Name)
            else None
        )
        if allowlist is None:
            try:
                allowlist = ast.literal_eval(comparator)
            except (TypeError, ValueError):
                return False
        if not isinstance(allowlist, (list, tuple, set, frozenset)):
            return False
        return all(
            isinstance(value, str)
            and len(value) == 1
            and value not in "<>&\"'"
            for value in allowlist
        )
    return False


def _python_html_encoder_output_is_safe(
    node: ast.AST,
    character_name: str,
    literals: dict[str, Any],
    raw_character_is_safe: bool,
) -> bool:
    if isinstance(node, ast.Constant):
        return _python_html_encoder_constant_is_safe(node.value)
    if isinstance(node, ast.Name):
        return node.id == character_name and raw_character_is_safe
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _python_html_encoder_output_is_safe(
            node.left,
            character_name,
            literals,
            raw_character_is_safe,
        ) and _python_html_encoder_output_is_safe(
            node.right,
            character_name,
            literals,
            raw_character_is_safe,
        )
    if not isinstance(node, ast.JoinedStr) or len(node.values) != 3:
        return False
    prefix, formatted, suffix = node.values
    if (
        not isinstance(prefix, ast.Constant)
        or not isinstance(prefix.value, str)
        or not isinstance(formatted, ast.FormattedValue)
        or formatted.conversion != -1
        or formatted.format_spec is not None
        or not isinstance(suffix, ast.Constant)
        or suffix.value != ";"
    ):
        return False
    token_kind = _python_html_entity_token_kind(
        formatted.value,
        character_name,
        literals,
    )
    return prefix.value in {
        "named": {"&"},
        "decimal": {"&#"},
        "hex": {"&#x", "&#X"},
    }.get(token_kind, set())


def _python_html_encoder_constant_is_safe(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if not any(character in value for character in "<>&\"'"):
        return True
    return re.fullmatch(
        r"(?:&(?:[A-Za-z][A-Za-z0-9]+|#[0-9]+|#[xX][0-9A-Fa-f]+);)+",
        value,
    ) is not None


def _python_html_entity_token_kind(
    node: ast.AST,
    character_name: str,
    literals: dict[str, Any],
) -> str | None:
    if isinstance(node, ast.Subscript):
        if (
            isinstance(node.value, ast.Name)
            and _python_call_is_ord_of(node.slice, character_name)
        ):
            entity_names = literals.get(node.value.id)
            if (
                isinstance(entity_names, dict)
                and bool(entity_names)
                and all(
                    isinstance(value, str)
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", value)
                    for value in entity_names.values()
                )
            ):
                return "named"
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "hex"
            and len(node.value.args) == 1
            and _python_call_is_ord_of(
                node.value.args[0],
                character_name,
            )
            and _python_html_hex_slice_is_exact(node.slice)
        ):
            return "hex"
    if _python_call_is_ord_of(node, character_name):
        return "decimal"
    return None


def _python_html_hex_slice_is_exact(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Slice)
        and isinstance(node.lower, ast.Constant)
        and node.lower.value == 2
        and node.upper is None
        and node.step is None
    )


def _python_call_is_ord_of(node: ast.AST, character_name: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ord"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == character_name
    )


def _classify_python_function_summaries(
    tree: ast.AST,
    sanitizer_definitions: list[tuple[str, bool]] | None = None,
) -> list[tuple[str, PythonFunctionSummary | None]]:
    sanitizer_status: dict[str, bool] = {}
    definitions = (
        sanitizer_definitions
        if sanitizer_definitions is not None
        else _classify_python_html_sanitizer_definitions(tree)
    )
    for name, verified in definitions:
        normalized_name = name.lower()
        sanitizer_status[normalized_name] = (
            sanitizer_status.get(normalized_name, True)
            and verified
        )
    verified_sanitizers = frozenset(
        name
        for name, verified in sanitizer_status.items()
        if verified
    )
    standard_sanitizer_calls = (
        _python_standard_html_sanitizer_calls_by_function(tree)
    )
    summaries: list[tuple[str, PythonFunctionSummary | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        trusted_sanitizers = verified_sanitizers.union(
            _python_trusted_standard_html_sanitizers(
                tree,
                node,
                standard_sanitizer_calls.get(node, {}),
            )
        )
        summary = _python_function_summary(node, trusted_sanitizers)
        if (
            summary is not None
            and summary.return_kind == "html_sanitized"
            and not _python_top_level_function_binding_is_stable(tree, node)
        ):
            summary = None
        summaries.append(
            (
                node.name,
                summary,
            )
        )
    return summaries


def _python_function_summary(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    verified_html_sanitizers: frozenset[str],
) -> PythonFunctionSummary | None:
    returns = [
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Return) and item.value is not None
    ]
    if not returns:
        return None
    if all(isinstance(value, ast.Constant) for value in returns):
        constants = {
            value.value
            for value in returns
            if isinstance(value, ast.Constant)
        }
        if len(constants) == 1:
            return PythonFunctionSummary(
                node.name,
                "constant",
                next(iter(constants)),
            )
        return None
    sanitizer_dependencies = _python_function_html_sanitizer_dependencies(
        node,
        verified_html_sanitizers,
    )
    if sanitizer_dependencies is not None:
        return PythonFunctionSummary(
            node.name,
            "html_sanitized",
            html_sanitizer_dependencies=sanitizer_dependencies,
        )
    rendered = " ".join(_node_text(value).lower() for value in returns)
    if any(
        marker in rendered
        for marker in (
            "request.",
            "self.request.",
            "get_form_parameter",
            "get_query_parameter",
            "get_cookie",
            "get_header",
            "get_json",
        )
    ):
        return PythonFunctionSummary(node.name, "request")
    return None


def _python_function_html_sanitizer_dependencies(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    verified_html_sanitizers: frozenset[str],
) -> frozenset[str] | None:
    """Summarize only straight-line returns whose tainted parts are HTML-safe."""

    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    env = {
        parameter.arg: _PythonHtmlSummaryValue(
            sources=frozenset({parameter.arg}),
            unsafe_sources=frozenset({parameter.arg}),
        )
        for parameter in parameters
    }
    returns: list[_PythonHtmlSummaryValue] = []
    for statement in node.body:
        if isinstance(statement, ast.Assign):
            value = _python_html_summary_eval(
                statement.value,
                env,
                verified_html_sanitizers,
            )
            names = [
                name
                for target in statement.targets
                for name in _target_names(target)
            ]
            if not names:
                return None
            for name in names:
                env[name] = value
            continue
        if isinstance(statement, ast.AnnAssign):
            if statement.value is None:
                continue
            names = _target_names(statement.target)
            if not names:
                return None
            value = _python_html_summary_eval(
                statement.value,
                env,
                verified_html_sanitizers,
            )
            for name in names:
                env[name] = value
            continue
        if isinstance(statement, ast.AugAssign):
            names = _target_names(statement.target)
            if len(names) != 1 or not isinstance(statement.op, ast.Add):
                return None
            current = env.get(
                names[0],
                _PythonHtmlSummaryValue(invalid=True),
            )
            env[names[0]] = _python_html_summary_merge(
                [
                    current,
                    _python_html_summary_eval(
                        statement.value,
                        env,
                        verified_html_sanitizers,
                    ),
                ]
            )
            continue
        if isinstance(statement, ast.Return):
            if statement.value is None:
                return None
            returns.append(
                _python_html_summary_eval(
                    statement.value,
                    env,
                    verified_html_sanitizers,
                )
            )
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass)):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        return None
    if not returns or not all(
        value.sources
        and not value.unsafe_sources
        and not value.invalid
        for value in returns
    ):
        return None
    return frozenset().union(
        *(value.html_sanitizer_dependencies for value in returns)
    )


def _python_html_summary_eval(
    node: ast.AST,
    env: dict[str, _PythonHtmlSummaryValue],
    verified_html_sanitizers: frozenset[str],
) -> _PythonHtmlSummaryValue:
    if isinstance(node, ast.Constant):
        return _PythonHtmlSummaryValue(
            constant=node.value,
            constant_known=True,
            trusted_constant=True,
        )
    if isinstance(node, ast.Name):
        return env.get(node.id, _PythonHtmlSummaryValue(invalid=True))
    if isinstance(node, ast.Attribute):
        value = _python_html_summary_eval(
            node.value,
            env,
            verified_html_sanitizers,
        )
        return _PythonHtmlSummaryValue(
            sources=value.sources,
            unsafe_sources=value.unsafe_sources,
            html_sanitizer_dependencies=value.html_sanitizer_dependencies,
            invalid=value.invalid,
        )
    if isinstance(node, ast.FormattedValue):
        value = _python_html_summary_eval(
            node.value,
            env,
            verified_html_sanitizers,
        )
        if node.conversion == -1 and node.format_spec is None:
            return value
        return _PythonHtmlSummaryValue(
            sources=value.sources,
            unsafe_sources=value.sources,
            html_sanitizer_dependencies=(
                value.html_sanitizer_dependencies
            ),
            invalid=True,
        )
    if isinstance(node, ast.JoinedStr):
        return _python_html_summary_merge(
            [
                _python_html_summary_eval(
                    value,
                    env,
                    verified_html_sanitizers,
                )
                for value in node.values
            ]
        )
    if isinstance(node, ast.BinOp):
        left = _python_html_summary_eval(
            node.left,
            env,
            verified_html_sanitizers,
        )
        right = _python_html_summary_eval(
            node.right,
            env,
            verified_html_sanitizers,
        )
        merged = _python_html_summary_merge([left, right])
        if (
            isinstance(node.op, ast.Add)
            and left.constant_known
            and right.constant_known
        ):
            try:
                return _PythonHtmlSummaryValue(
                    constant=left.constant + right.constant,
                    constant_known=True,
                    trusted_constant=True,
                    html_sanitizer_dependencies=(
                        merged.html_sanitizer_dependencies
                    ),
                )
            except Exception:
                return merged
        return merged
    if isinstance(node, ast.IfExp):
        return _python_html_summary_merge(
            [
                _python_html_summary_eval(
                    node.body,
                    env,
                    verified_html_sanitizers,
                ),
                _python_html_summary_eval(
                    node.orelse,
                    env,
                    verified_html_sanitizers,
                ),
            ]
        )
    if isinstance(node, ast.Subscript):
        container = _python_html_summary_eval(
            node.value,
            env,
            verified_html_sanitizers,
        )
        key = _python_html_summary_eval(
            node.slice,
            env,
            verified_html_sanitizers,
        )
        if key.sources or key.invalid:
            return _python_html_summary_mark_unsafe(
                _python_html_summary_merge([container, key])
            )
        return container
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _python_html_summary_merge(
            [
                _python_html_summary_eval(
                    value,
                    env,
                    verified_html_sanitizers,
                )
                for value in node.elts
            ]
        )
    if isinstance(node, ast.Dict):
        return _python_html_summary_merge(
            [
                _python_html_summary_eval(
                    value,
                    env,
                    verified_html_sanitizers,
                )
                for value in node.values
            ]
        )
    if isinstance(node, ast.Call):
        name = _call_name(node.func).lower()
        values = [
            _python_html_summary_eval(
                value,
                env,
                verified_html_sanitizers,
            )
            for value in node.args
        ]
        values.extend(
            _python_html_summary_eval(
                keyword.value,
                env,
                verified_html_sanitizers,
            )
            for keyword in node.keywords
        )
        if _python_is_request_source_call(name):
            return _PythonHtmlSummaryValue(
                sources=frozenset({"__request__"}),
                unsafe_sources=frozenset({"__request__"}),
            )
        if _python_is_html_sanitizer_call(
            name,
            verified_html_sanitizers,
        ):
            merged = _python_html_summary_merge(values)
            sanitizer_dependency = _python_html_sanitizer_dependency(
                name,
                verified_html_sanitizers,
            )
            return _PythonHtmlSummaryValue(
                sources=merged.sources,
                unsafe_sources=frozenset(),
                html_sanitizer_dependencies=(
                    merged.html_sanitizer_dependencies.union(
                        {sanitizer_dependency}
                        if sanitizer_dependency is not None
                        else ()
                    )
                ),
                trusted_constant=(
                    not merged.sources
                    and not merged.invalid
                    and all(
                        value.constant_known or value.trusted_constant
                        for value in values
                    )
                ),
            )
        if isinstance(node.func, ast.Attribute):
            receiver = _python_html_summary_eval(
                node.func.value,
                env,
                verified_html_sanitizers,
            )
            if node.func.attr == "replace":
                return _python_html_summary_replace(receiver, values)
            values.append(receiver)
        return _python_html_summary_mark_unsafe(
            _python_html_summary_merge(values)
        )
    children = [
        _python_html_summary_eval(
            child,
            env,
            verified_html_sanitizers,
        )
        for child in ast.iter_child_nodes(node)
        if isinstance(child, ast.expr)
    ]
    return _python_html_summary_mark_unsafe(
        _python_html_summary_merge(children)
    )


def _python_html_summary_replace(
    receiver: _PythonHtmlSummaryValue,
    args: list[_PythonHtmlSummaryValue],
) -> _PythonHtmlSummaryValue:
    if receiver.invalid or len(args) < 2:
        return _PythonHtmlSummaryValue(invalid=True)
    if any(value.sources or value.invalid for value in args):
        return _python_html_summary_mark_unsafe(
            _python_html_summary_merge([receiver, *args])
        )
    if not all(
        value.constant_known or value.trusted_constant
        for value in args
    ):
        return _PythonHtmlSummaryValue(invalid=True)
    _old, new = args[:2]
    if not _python_html_replacement_preserves_safety(
        new.constant,
        new.constant_known,
    ):
        return _python_html_summary_mark_unsafe(receiver)
    return receiver


def _python_html_replacement_preserves_safety(
    value: Any,
    constant_known: bool,
) -> bool:
    if not constant_known or not isinstance(value, str):
        return False
    return (
        not any(character in value for character in "<>&\"'")
        or _python_html_replacement_is_inert(value)
    )


def _python_html_replacement_is_inert(value: str) -> bool:
    return value.casefold() in {"<br>", "<br/>", "<br />"}


def _python_constant_format_preserves_html(
    template: Any,
    constant_known: bool,
) -> bool:
    if not constant_known or not isinstance(template, str):
        return False
    return _python_constant_format_template_preserves_html(template)


@lru_cache(maxsize=512)
def _python_constant_format_template_preserves_html(template: str) -> bool:
    try:
        fields = string.Formatter().parse(template)
        return all(
            conversion is None and not format_spec
            for _literal, field_name, format_spec, conversion in fields
            if field_name is not None
        )
    except ValueError:
        return False


def _python_security_without_sanitizer_domain(
    value: PythonSecurityValue,
    domain: str,
) -> PythonSecurityValue:
    return PythonSecurityValue(
        value.tainted,
        value.source_line,
        value.constant,
        value.constant_known,
        value.sanitized_for.difference({domain}),
    )


def _python_html_summary_merge(
    values: list[_PythonHtmlSummaryValue],
) -> _PythonHtmlSummaryValue:
    if not values:
        return _PythonHtmlSummaryValue(
            constant="",
            constant_known=True,
            trusted_constant=True,
        )
    sources = frozenset().union(
        *(value.sources for value in values)
    )
    unsafe_sources = frozenset().union(
        *(value.unsafe_sources for value in values)
    )
    html_sanitizer_dependencies = frozenset().union(
        *(value.html_sanitizer_dependencies for value in values)
    )
    no_sources = not sources
    return _PythonHtmlSummaryValue(
        sources=sources,
        unsafe_sources=unsafe_sources,
        html_sanitizer_dependencies=html_sanitizer_dependencies,
        trusted_constant=(
            no_sources
            and all(
                value.constant_known or value.trusted_constant
                for value in values
            )
        ),
        invalid=any(value.invalid for value in values),
    )


def _python_html_summary_mark_unsafe(
    value: _PythonHtmlSummaryValue,
) -> _PythonHtmlSummaryValue:
    return _PythonHtmlSummaryValue(
        sources=value.sources,
        unsafe_sources=value.sources,
        html_sanitizer_dependencies=value.html_sanitizer_dependencies,
        invalid=value.invalid,
    )


def _python_is_request_source_call(name: str) -> bool:
    return (
        name.startswith(
            (
                "request.args.",
                "request.form.",
                "request.cookies.",
                "request.headers.",
                "request.values.",
            )
        )
        or name in {"request.get_json", "input"}
        or name.endswith(
            (
                "get_form_parameter",
                "get_query_parameter",
                "get_header",
                "get_cookie",
                "get_parameter",
                "get_json",
                "request_wrapper",
            )
        )
    )


_PYTHON_STANDARD_HTML_SANITIZERS = frozenset(
    {
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
    }
)


def _python_direct_imported_module_bindings(
    scope: ast.AST,
) -> dict[str, set[tuple[str, int]]]:
    bindings: dict[str, set[tuple[str, int]]] = {}
    for statement in getattr(scope, "body", []):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                imported_name = alias.name if alias.asname else local_name
                bindings.setdefault(local_name.casefold(), set()).add(
                    (imported_name.casefold(), statement.lineno)
                )
        elif isinstance(statement, ast.ImportFrom):
            module_name = (statement.module or "").strip(".")
            for alias in statement.names:
                local_name = alias.asname or alias.name
                imported_name = ".".join(
                    part for part in (module_name, alias.name) if part
                )
                bindings.setdefault(local_name.casefold(), set()).add(
                    (imported_name.casefold(), statement.lineno)
                )
    return bindings


def _python_trusted_standard_html_sanitizers(
    tree: ast.AST,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    sanitizer_calls: dict[str, list[ast.Call]],
) -> frozenset[str]:
    if not sanitizer_calls:
        return frozenset()
    function_bindings = _python_direct_imported_module_bindings(node)
    module_bindings = _python_direct_imported_module_bindings(tree)
    parameter_names = {
        parameter.arg.casefold()
        for parameter in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
    }
    if node.args.vararg is not None:
        parameter_names.add(node.args.vararg.arg.casefold())
    if node.args.kwarg is not None:
        parameter_names.add(node.args.kwarg.arg.casefold())
    trusted: set[str] = set()
    for sanitizer, calls in sanitizer_calls.items():
        root_name = sanitizer.split(".", 1)[0]
        if (
            root_name in parameter_names
            or _python_scope_may_replace_call_binding(tree, sanitizer)
            or _python_scope_may_replace_call_binding(node, sanitizer)
        ):
            continue
        if root_name in function_bindings:
            bindings = function_bindings[root_name]
            if (
                len(bindings) == 1
                and next(iter(bindings))[0] == root_name
                and next(iter(bindings))[1]
                < min(candidate.lineno for candidate in calls)
            ):
                trusted.add(sanitizer)
            continue
        bindings = module_bindings.get(root_name, set())
        if len(bindings) == 1 and next(iter(bindings))[0] == root_name:
            trusted.add(sanitizer)
    return frozenset(trusted)


def _python_standard_html_sanitizer_calls_by_function(
    tree: ast.AST,
) -> dict[
    ast.FunctionDef | ast.AsyncFunctionDef,
    dict[str, list[ast.Call]],
]:
    calls: dict[
        ast.FunctionDef | ast.AsyncFunctionDef,
        dict[str, list[ast.Call]],
    ] = {}

    def visit(
        candidate: ast.AST,
        current_function: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> None:
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for statement in candidate.body:
                visit(statement, candidate)
            return
        if isinstance(candidate, ast.Lambda):
            return
        if isinstance(candidate, ast.Call) and current_function is not None:
            name = _call_name(candidate.func).casefold()
            if name in _PYTHON_STANDARD_HTML_SANITIZERS:
                calls.setdefault(current_function, {}).setdefault(
                    name,
                    [],
                ).append(candidate)
        for child in ast.iter_child_nodes(candidate):
            visit(child, current_function)

    visit(tree, None)
    return calls


def _python_html_sanitizer_dependency(
    name: str,
    trusted_html_sanitizers: frozenset[str],
) -> str | None:
    if name not in trusted_html_sanitizers:
        return None
    if name in _PYTHON_STANDARD_HTML_SANITIZERS:
        return name
    return None if "." in name else name


def _python_is_html_sanitizer_call(
    name: str,
    trusted_html_sanitizers: frozenset[str],
) -> bool:
    return name in trusted_html_sanitizers


def _collect_python_weak_prefix_guard_summaries(
    tree: ast.AST,
    path: Path,
) -> list[PythonWeakPrefixGuardSummary]:
    summaries: list[PythonWeakPrefixGuardSummary] = []
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.FunctionDef):
            continue
        parameters = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        matches = [
            index
            for index, parameter in enumerate(parameters)
            if _python_function_is_proven_weak_prefix_guard(
                node,
                parameter.arg,
            )
        ]
        if (
            len(matches) != 1
            or not _python_top_level_function_binding_is_stable(tree, node)
        ):
            continue
        summaries.append(
            PythonWeakPrefixGuardSummary(
                name=node.name,
                file=str(path),
                param_names=tuple(parameter.arg for parameter in parameters),
                guarded_param_index=matches[0],
            )
        )
    return summaries


def _python_function_is_proven_weak_prefix_guard(
    function: ast.FunctionDef,
    parameter_name: str,
) -> bool:
    unsupported = (
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
        ast.Assign,
        ast.AnnAssign,
        ast.AugAssign,
        ast.NamedExpr,
        ast.Lambda,
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Delete,
    )
    for node in ast.walk(function):
        if node is not function and isinstance(node, unsupported):
            return False

    returns = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Return)
    ]
    if not returns or any(
        not isinstance(node.value, ast.Constant)
        or not isinstance(node.value.value, bool)
        for node in returns
    ):
        return False
    if not any(node.value.value is True for node in returns):
        return False
    if not any(node.value.value is False for node in returns):
        return False

    parents = {
        child: parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    saw_weak_prefix = False
    for return_node in returns:
        if return_node.value.value is not True:
            continue
        current: ast.AST = return_node
        while current in parents:
            parent = parents[current]
            if isinstance(parent, ast.If) and _python_ast_uses_name(
                parent.test,
                parameter_name,
            ):
                if (
                    current not in parent.body
                    or not _python_is_literal_weak_prefix_test(
                        parent.test,
                        parameter_name,
                    )
                ):
                    return False
                saw_weak_prefix = True
            current = parent
            if current is function:
                break

    allowed_parameter_name_nodes = {
        id(node.func.value)
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _python_is_literal_weak_prefix_test(node, parameter_name)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    }
    return saw_weak_prefix and all(
        id(node) in allowed_parameter_name_nodes
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == parameter_name
    )


def _python_ast_uses_name(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(child, ast.Name)
        and child.id == name
        for child in ast.walk(node)
    )


def _python_is_literal_weak_prefix_test(
    node: ast.AST,
    parameter_name: str,
) -> bool:
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Attribute)
        or node.func.attr != "startswith"
        or not isinstance(node.func.value, ast.Name)
        or node.func.value.id != parameter_name
        or len(node.args) != 1
        or node.keywords
    ):
        return False
    prefixes = node.args[0]
    values = (
        list(prefixes.elts)
        if isinstance(prefixes, (ast.Tuple, ast.List, ast.Set))
        else [prefixes]
    )
    return bool(values) and all(
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and bool(value.value)
        for value in values
    )


def _collect_python_sink_summaries(tree: ast.AST, path: Path, lines: list[str]) -> list[PythonSinkSummary]:
    summaries: list[PythonSinkSummary] = []
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        param_names = tuple(parameter.arg for parameter in parameters)
        if not param_names:
            continue
        dependencies: dict[str, set[int]] = {name: {index} for index, name in enumerate(param_names)}
        assignments = [item for item in ast.walk(node) if isinstance(item, (ast.Assign, ast.AnnAssign))]
        for _ in range(3):
            changed = False
            for assignment in assignments:
                value = assignment.value
                if value is None:
                    continue
                source_indexes = _python_expr_param_dependencies(value, dependencies)
                targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                for target in targets:
                    for name in _target_names(target):
                        before = dependencies.get(name, set())
                        after = before.union(source_indexes)
                        if after != before:
                            dependencies[name] = after
                            changed = True
            if not changed:
                break
        sink_records: list[tuple[ast.Call, str, tuple[int, ...]]] = []
        for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
            rule_id, expressions = _python_summary_sink(call)
            if not rule_id:
                continue
            dangerous = tuple(
                sorted(
                    {
                        index
                        for expression in expressions
                        for index in _python_expr_param_dependencies(
                            expression,
                            dependencies,
                        )
                    }
                )
            )
            if dangerous:
                sink_records.append((call, rule_id, dangerous))
        seen: set[tuple[str, tuple[int, ...]]] = set()
        for call, rule_id, dangerous in sink_records:
            key = (rule_id, dangerous)
            if key in seen:
                continue
            seen.add(key)
            same_dependency_sinks = [
                candidate
                for candidate in sink_records
                if candidate[1:] == (rule_id, dangerous)
            ]
            proven_command_primitive = None
            if (
                rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
                and len(same_dependency_sinks) == 1
            ):
                proven_command_primitive = (
                    _python_proven_summary_command_primitive(
                        tree,
                        node,
                        call,
                        dangerous,
                        dependencies,
                    )
                )
            summaries.append(
                PythonSinkSummary(
                    name=node.name,
                    file=str(path),
                    line=call.lineno,
                    line_hash=_line_hash(lines, call.lineno),
                    rule_id=rule_id,
                    param_names=param_names,
                    dangerous_param_indexes=dangerous,
                    proven_command_primitive=proven_command_primitive,
                )
            )
    return summaries


def _python_proven_summary_command_primitive(
    tree: ast.AST,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    dangerous_param_indexes: tuple[int, ...],
    dependencies: dict[str, set[int]],
) -> str | None:
    primitive = _python_shell_command_primitive(call)
    if primitive is None:
        return None
    if not _python_top_level_function_binding_is_stable(tree, function):
        return None
    if not _python_shell_primitive_binding_is_stable(
        tree,
        function,
        primitive,
    ):
        return None
    if _python_call_has_constraining_parameter_guard(
        function,
        call,
        frozenset(dangerous_param_indexes),
        dependencies,
    ):
        return None
    return primitive


def _python_shell_command_primitive(call: ast.Call) -> str | None:
    name = _call_name(call.func).lower()
    return name if name in {"os.system", "os.popen"} else None


def _python_shell_primitive_binding_is_stable(
    tree: ast.AST,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    primitive: str,
) -> bool:
    root_name = primitive.split(".", 1)[0]
    imported_modules: set[str] = set()
    for statement in getattr(tree, "body", []):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = (alias.asname or alias.name.split(".", 1)[0]).casefold()
                if local_name == root_name:
                    imported_modules.add(alias.name.casefold())
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                local_name = (alias.asname or alias.name).casefold()
                if local_name == root_name:
                    imported_modules.add(
                        ".".join(
                            part
                            for part in (
                                str(statement.module or "").casefold(),
                                alias.name.casefold(),
                            )
                            if part
                        )
                    )
    parameters = {
        parameter.arg.casefold()
        for parameter in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    if function.args.vararg is not None:
        parameters.add(function.args.vararg.arg.casefold())
    if function.args.kwarg is not None:
        parameters.add(function.args.kwarg.arg.casefold())
    return (
        imported_modules == {root_name}
        and root_name not in parameters
        and not _python_scope_may_replace_call_binding(tree, primitive)
        and not _python_scope_may_replace_call_binding(function, primitive)
    )


def _python_call_has_constraining_parameter_guard(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    dangerous_param_indexes: frozenset[int],
    dependencies: dict[str, set[int]],
) -> bool:
    parents = {
        child: parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    current: ast.AST = call
    while current in parents:
        current = parents[current]
        test: ast.AST | None = None
        if isinstance(current, (ast.If, ast.While, ast.IfExp)):
            test = current.test
        elif isinstance(current, ast.match_case):
            test = current.guard
        if (
            test is not None
            and _python_expr_param_dependencies(test, dependencies).intersection(
                dangerous_param_indexes
            )
            and not _python_is_bare_truthiness_guard(
                test,
                dependencies,
                dangerous_param_indexes,
            )
        ):
            return True
        if current is function:
            break
    return False


def _python_is_bare_truthiness_guard(
    test: ast.AST,
    dependencies: dict[str, set[int]] | None = None,
    dangerous_param_indexes: frozenset[int] | None = None,
) -> bool:
    candidate = test.operand if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) else test
    if not isinstance(candidate, ast.Name):
        return False
    if dependencies is None or dangerous_param_indexes is None:
        return True
    return bool(
        dependencies.get(candidate.id, set()).intersection(
            dangerous_param_indexes
        )
    )


def _python_expr_param_dependencies(node: ast.AST, dependencies: dict[str, set[int]]) -> set[int]:
    indexes: set[int] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            indexes.update(dependencies.get(child.id, set()))
    return indexes


def _python_summary_sink(node: ast.Call) -> tuple[str | None, list[ast.AST]]:
    name = _call_name(node.func).lower()
    if name.endswith((".execute", ".executemany", ".query", ".raw")):
        return "WEB_UNTRUSTED_INPUT_TO_SQL", list(node.args[:1])
    if name in {"os.system", "os.popen", "eval", "exec"} or name.endswith(
        ("subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_output")
    ):
        return "WEB_UNTRUSTED_INPUT_TO_COMMAND", [*node.args, *[keyword.value for keyword in node.keywords]]
    if name.startswith(("requests.", "httpx.", "urllib.request.")):
        return "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST", list(node.args[:1])
    path_names = {"open", "codecs.open", "io.open", "pathlib.path", "path", "send_file", "send_from_directory"}
    if name in path_names or name == "os.path.exists" or name.endswith(
        (".open", ".read_text", ".write_text", ".read_bytes", ".write_bytes")
    ):
        return "WEB_UNTRUSTED_INPUT_TO_FILE_PATH", list(node.args[:1])
    return None, []


def _python_summary_matches_module(summary: PythonSinkSummary, module_name: str) -> bool:
    return _python_source_file_matches_module(summary.file, module_name)


def _python_unconditional_import_nodes(tree: ast.AST) -> list[ast.stmt]:
    imports: list[ast.stmt] = []
    pending = list(getattr(tree, "body", []))
    while pending:
        statement = pending.pop(0)
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            imports.append(statement)
        elif isinstance(
            statement,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            pending[0:0] = list(statement.body)
    return imports


def _python_nodes_in_lexical_scope(scope: ast.AST) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    pending = list(reversed(getattr(scope, "body", [])))
    while pending:
        node = pending.pop()
        nodes.append(node)
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


_PYTHON_DYNAMIC_BINDING_CALLS = frozenset(
    {"eval", "exec", "globals", "locals", "setattr", "vars"}
)


def _python_scope_name_aliases(
    nodes: list[ast.AST],
    seeds: set[str],
) -> set[str]:
    aliases = {name.casefold() for name in seeds}
    changed = True
    while changed:
        changed = False
        for node in nodes:
            targets: list[ast.AST] = []
            value: ast.AST | None = None
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
                value = node.value
            elif isinstance(node, ast.NamedExpr):
                targets = [node.target]
                value = node.value
            if value is not None:
                source_name = _call_name(value).casefold()
                source_terminal = source_name.rsplit(".", 1)[-1]
                source_is_alias = source_name in aliases or (
                    source_name.startswith("builtins.")
                    and source_terminal in aliases
                )
                if source_is_alias:
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id.casefold() not in aliases
                        ):
                            aliases.add(target.id.casefold())
                            changed = True
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").casefold() == "builtins"
            ):
                for alias in node.names:
                    if alias.name.casefold() not in aliases:
                        continue
                    local_name = (alias.asname or alias.name).casefold()
                    if local_name not in aliases:
                        aliases.add(local_name)
                        changed = True
    return aliases


def _python_match_bound_names(pattern: ast.pattern) -> set[str]:
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name is not None:
            names.add(pattern.name.casefold())
        if pattern.pattern is not None:
            names.update(_python_match_bound_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            names.add(pattern.name.casefold())
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest is not None:
            names.add(pattern.rest.casefold())
        for child in pattern.patterns:
            names.update(_python_match_bound_names(child))
    elif isinstance(pattern, ast.MatchSequence):
        for child in pattern.patterns:
            names.update(_python_match_bound_names(child))
    elif isinstance(pattern, ast.MatchClass):
        for child in [*pattern.patterns, *pattern.kwd_patterns]:
            names.update(_python_match_bound_names(child))
    elif isinstance(pattern, ast.MatchOr):
        for child in pattern.patterns:
            names.update(_python_match_bound_names(child))
    return names


def _python_function_may_mutate_enclosing_call_binding(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    call_parts: tuple[str, ...],
) -> bool:
    root_name = call_parts[0]
    nodes = _python_nodes_in_lexical_scope(node)
    declarations = {
        name.casefold()
        for candidate in nodes
        if isinstance(candidate, (ast.Global, ast.Nonlocal))
        for name in candidate.names
    }
    if root_name in declarations and any(
        isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and candidate.id.casefold() == root_name
        for candidate in nodes
    ):
        return True
    dynamic_aliases = _python_scope_name_aliases(
        nodes,
        set(_PYTHON_DYNAMIC_BINDING_CALLS),
    )
    for candidate in nodes:
        if isinstance(candidate, ast.Attribute) and isinstance(
            candidate.ctx,
            (ast.Store, ast.Del),
        ):
            target_parts = tuple(
                part.casefold()
                for part in _call_name(candidate).split(".")
                if part
            )
            if (
                target_parts
                and len(target_parts) <= len(call_parts)
                and call_parts[: len(target_parts)] == target_parts
            ):
                return True
        if isinstance(candidate, ast.Call):
            dynamic_name = _call_name(candidate.func).casefold()
            if dynamic_name in dynamic_aliases or (
                dynamic_name.startswith("builtins.")
                and dynamic_name.rsplit(".", 1)[-1] in dynamic_aliases
            ):
                return True
        if isinstance(candidate, ast.Attribute):
            attribute_name = _call_name(candidate).casefold()
            if attribute_name == "sys.modules" or attribute_name.startswith(
                "sys.modules.",
            ):
                return True
    return False


def _python_called_local_function_names(
    nodes: list[ast.AST],
    definition_names: set[str],
    extra_called_names: set[str] | None = None,
) -> set[str]:
    alias_sources: dict[str, str] = {}
    for node in nodes:
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.NamedExpr):
            targets = [node.target]
            value = node.value
        if not isinstance(value, ast.Name):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                alias_sources[target.id.casefold()] = value.id.casefold()
    called_definitions: set[str] = set()
    called_names = {
        _call_name(node.func).casefold()
        for node in nodes
        if isinstance(node, ast.Call)
    }
    if extra_called_names:
        called_names.update(name.casefold() for name in extra_called_names)
    for called_name in called_names:
        if "." in called_name:
            continue
        seen: set[str] = set()
        while called_name not in seen:
            if called_name in definition_names:
                called_definitions.add(called_name)
                break
            seen.add(called_name)
            if called_name not in alias_sources:
                break
            called_name = alias_sources[called_name]
    return called_definitions


def _python_function_parent_scopes(
    tree: ast.AST,
) -> dict[ast.FunctionDef | ast.AsyncFunctionDef, ast.AST]:
    parents: dict[
        ast.FunctionDef | ast.AsyncFunctionDef,
        ast.AST,
    ] = {}

    def visit_scope(scope: ast.AST) -> None:
        children = [
            candidate
            for candidate in _python_nodes_in_lexical_scope(scope)
            if isinstance(
                candidate,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            )
        ]
        for child in children:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parents[child] = scope
            visit_scope(child)

    visit_scope(tree)
    return parents


def _python_definition_header_expressions(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    expressions: list[ast.AST] = [
        *node.decorator_list,
        *node.args.defaults,
        *(
            default
            for default in node.args.kw_defaults
            if default is not None
        ),
    ]
    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if node.args.vararg is not None:
        parameters.append(node.args.vararg)
    if node.args.kwarg is not None:
        parameters.append(node.args.kwarg)
    expressions.extend(
        parameter.annotation
        for parameter in parameters
        if parameter.annotation is not None
    )
    if node.returns is not None:
        expressions.append(node.returns)
    expressions.extend(getattr(node, "type_params", []))
    return expressions


def _python_definition_header_may_replace_call_binding(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_scope: ast.AST,
    call_name: str,
) -> bool:
    expressions = _python_definition_header_expressions(node)
    if not expressions:
        return False
    header_nodes = [
        candidate
        for expression in expressions
        for candidate in ast.walk(expression)
    ]
    implicit_decorator_calls = {
        _call_name(decorator).casefold()
        for decorator in node.decorator_list
        if not isinstance(decorator, ast.Call)
    }
    explicit_calls = {
        _call_name(candidate.func).casefold()
        for candidate in header_nodes
        if isinstance(candidate, ast.Call)
    }
    unqualified_calls = {
        name
        for name in explicit_calls.union(implicit_decorator_calls)
        if name and "." not in name
    }
    parent_nodes = _python_nodes_in_lexical_scope(parent_scope)
    dynamic_aliases = _python_scope_name_aliases(
        parent_nodes,
        set(_PYTHON_DYNAMIC_BINDING_CALLS),
    )
    if any(name in dynamic_aliases for name in unqualified_calls):
        return True
    if any(
        isinstance(candidate, ast.Attribute)
        and (
            _call_name(candidate).casefold() == "sys.modules"
            or _call_name(candidate).casefold().startswith("sys.modules.")
        )
        for candidate in header_nodes
    ):
        return True
    definitions = [
        candidate
        for candidate in parent_nodes
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    called_definitions = _python_called_local_function_names(
        parent_nodes,
        {candidate.name.casefold() for candidate in definitions},
        unqualified_calls,
    )
    call_parts = tuple(
        part.casefold() for part in call_name.split(".") if part
    )
    return any(
        candidate.name.casefold() in called_definitions
        and _python_function_may_mutate_enclosing_call_binding(
            candidate,
            call_parts,
        )
        for candidate in definitions
    )


def _python_definition_header_requires_binding_review(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    expressions = _python_definition_header_expressions(node)
    if not expressions:
        return False
    header_nodes = [
        candidate
        for expression in expressions
        for candidate in ast.walk(expression)
    ]
    called_names = {
        _call_name(candidate.func).casefold()
        for candidate in header_nodes
        if isinstance(candidate, ast.Call)
    }
    called_names.update(
        _call_name(decorator).casefold()
        for decorator in node.decorator_list
        if not isinstance(decorator, ast.Call)
    )
    if any(name and "." not in name for name in called_names):
        return True
    if any(
        name.startswith("builtins.")
        and name.rsplit(".", 1)[-1] in _PYTHON_DYNAMIC_BINDING_CALLS
        for name in called_names
    ):
        return True
    return any(
        isinstance(candidate, ast.Attribute)
        and (
            _call_name(candidate).casefold() == "sys.modules"
            or _call_name(candidate).casefold().startswith("sys.modules.")
        )
        for candidate in header_nodes
    )


def _python_class_definition_may_replace_call_binding(
    node: ast.ClassDef,
    call_parts: tuple[str, ...],
    binding_resolution_nodes: list[ast.AST],
) -> bool:
    root_name = call_parts[0]
    header_expressions: list[ast.AST] = [
        *node.decorator_list,
        *node.bases,
        *(keyword.value for keyword in node.keywords),
        *getattr(node, "type_params", []),
    ]
    header_nodes = [
        candidate
        for expression in header_expressions
        for candidate in ast.walk(expression)
    ]
    class_nodes = _python_nodes_in_lexical_scope(node)
    resolution_nodes = [*binding_resolution_nodes, *class_nodes]
    declarations = {
        name.casefold()
        for candidate in class_nodes
        if isinstance(candidate, (ast.Global, ast.Nonlocal))
        for name in candidate.names
    }
    if root_name in declarations and any(
        isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and candidate.id.casefold() == root_name
        for candidate in class_nodes
    ):
        return True
    if any(
        isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and candidate.id.casefold() == root_name
        for candidate in header_nodes
    ):
        return True

    dynamic_aliases = _python_scope_name_aliases(
        resolution_nodes,
        set(_PYTHON_DYNAMIC_BINDING_CALLS),
    )
    definitions = [
        candidate
        for candidate in resolution_nodes
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    mutator_names = {
        candidate.name.casefold()
        for candidate in definitions
        if _python_function_may_mutate_enclosing_call_binding(
            candidate,
            call_parts,
        )
    }
    mutator_aliases = _python_scope_name_aliases(
        resolution_nodes,
        mutator_names,
    )
    called_names = {
        _call_name(candidate.func).casefold()
        for candidate in [*header_nodes, *class_nodes]
        if isinstance(candidate, ast.Call)
    }
    called_names.update(
        _call_name(decorator).casefold()
        for decorator in node.decorator_list
        if not isinstance(decorator, ast.Call)
    )
    if any(
        name in dynamic_aliases
        or name in mutator_aliases
        or (
            name.startswith("builtins.")
            and name.rsplit(".", 1)[-1]
            in dynamic_aliases.union(mutator_aliases)
        )
        for name in called_names
    ):
        return True

    for candidate in [*header_nodes, *class_nodes]:
        if isinstance(candidate, ast.Attribute) and isinstance(
            candidate.ctx,
            (ast.Store, ast.Del),
        ):
            target_parts = tuple(
                part.casefold()
                for part in _call_name(candidate).split(".")
                if part
            )
            if (
                target_parts
                and len(target_parts) <= len(call_parts)
                and call_parts[: len(target_parts)] == target_parts
            ):
                return True
        if isinstance(candidate, ast.Attribute):
            attribute_name = _call_name(candidate).casefold()
            if attribute_name == "sys.modules" or attribute_name.startswith(
                "sys.modules.",
            ):
                return True

    return any(
        _python_class_definition_may_replace_call_binding(
            candidate,
            call_parts,
            binding_resolution_nodes,
        )
        for candidate in class_nodes
        if isinstance(candidate, ast.ClassDef)
    )


def _python_scope_may_replace_call_binding(
    scope: ast.AST,
    call_name: str,
    *,
    allowed_definition: str | None = None,
    allow_active_local_prefix: bool = False,
    binding_resolution_nodes: list[ast.AST] | None = None,
    ignore_star_imports: bool = False,
) -> bool:
    call_parts = tuple(part.casefold() for part in call_name.split(".") if part)
    if not call_parts:
        return True
    root_name = call_parts[0]
    nodes = _python_nodes_in_lexical_scope(scope)
    resolution_nodes = [
        *nodes,
        *(binding_resolution_nodes or []),
    ]
    if any(
        _python_class_definition_may_replace_call_binding(
            node,
            call_parts,
            resolution_nodes,
        )
        for node in nodes
        if isinstance(node, ast.ClassDef)
    ):
        return True
    dynamic_aliases = _python_scope_name_aliases(
        nodes,
        set(_PYTHON_DYNAMIC_BINDING_CALLS),
    )
    function_definitions = [
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    called_function_names = _python_called_local_function_names(
        nodes,
        {node.name.casefold() for node in function_definitions},
    )
    mutator_names = {
        node.name.casefold()
        for node in function_definitions
        if node.name.casefold() in called_function_names
        and _python_function_may_mutate_enclosing_call_binding(
            node,
            call_parts,
        )
    }
    mutator_aliases = _python_scope_name_aliases(nodes, mutator_names)
    for node in nodes:
        if (
            not ignore_star_imports
            and isinstance(node, ast.ImportFrom)
            and any(
            alias.name == "*" for alias in node.names
            )
        ):
            return True
        if (
            isinstance(node, ast.ExceptHandler)
            and node.name is not None
            and node.name.casefold() == root_name
        ):
            return True
        if isinstance(node, ast.Match) and any(
            root_name in _python_match_bound_names(case.pattern)
            for case in node.cases
        ):
            return True
        if isinstance(node, ast.Name) and isinstance(
            node.ctx,
            (ast.Store, ast.Del),
        ):
            if node.id.casefold() == root_name:
                return True
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ) and node.name.casefold() == root_name:
            if not (
                allowed_definition == root_name
                and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and (
                    _python_same_file_request_function_binding_is_stable(
                        scope,
                        node,
                    )
                    if allow_active_local_prefix
                    else _python_top_level_function_binding_is_stable(
                        scope,
                        node,
                    )
                )
            ):
                return True
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx,
            (ast.Store, ast.Del),
        ):
            target_parts = tuple(
                part.casefold()
                for part in _call_name(node).split(".")
                if part
            )
            if (
                target_parts
                and len(target_parts) <= len(call_parts)
                and call_parts[: len(target_parts)] == target_parts
            ):
                return True
        if isinstance(node, ast.Call):
            dynamic_name = _call_name(node.func).casefold()
            if (
                dynamic_name in dynamic_aliases
                or dynamic_name in mutator_aliases
                or (
                    dynamic_name.startswith("builtins.")
                    and dynamic_name.rsplit(".", 1)[-1]
                    in dynamic_aliases
                )
            ):
                return True
        if isinstance(node, ast.Attribute):
            attribute_name = _call_name(node).casefold()
            if attribute_name == "sys.modules" or attribute_name.startswith(
                "sys.modules.",
            ):
                return True
    return False


def _python_source_file_matches_module(
    source_file: str,
    module_name: str,
) -> bool:
    module_path = module_name.strip(".").replace(".", "/").casefold()
    if not module_path:
        return False
    source_path = source_file.replace("\\", "/").casefold()
    return source_path.endswith(f"/{module_path}.py") or source_path.endswith(
        f"/{module_path}/__init__.py"
    )


def _python_import_module(path: Path, module: str | None, level: int) -> str:
    if level <= 0:
        return str(module or "")
    package_parts: list[str] = []
    parent = path.resolve().parent
    while (parent / "__init__.py").is_file():
        package_parts.insert(0, parent.name)
        parent = parent.parent
    keep = max(0, len(package_parts) - (level - 1))
    resolved = package_parts[:keep]
    if module:
        resolved.extend(str(module).split("."))
    return ".".join(resolved)


def _python_star_import_excludes_name(
    importing_path: Path,
    node: ast.ImportFrom,
    name: str,
) -> bool:
    module = _python_import_module(
        importing_path,
        node.module,
        node.level,
    )
    if not module:
        return False
    module_path = Path(*module.split("."))
    candidates: list[Path] = []
    for parent in importing_path.resolve().parents:
        for candidate in (
            parent / module_path.with_suffix(".py"),
            parent / module_path / "__init__.py",
        ):
            if candidate.is_file() and candidate not in candidates:
                candidates.append(candidate)
    if len(candidates) != 1:
        return False
    try:
        tree = ast.parse(
            candidates[0].read_text(encoding="utf-8"),
            filename=str(candidates[0]),
        )
    except (OSError, SyntaxError, UnicodeError):
        return False
    exported = _python_static_module_exports(tree)
    return exported is not None and name not in exported


def _python_static_module_exports(
    tree: ast.AST,
) -> frozenset[str] | None:
    body = list(getattr(tree, "body", []))
    for statement in body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if not any(
            isinstance(target, ast.Name)
            and target.id == "__all__"
            for target in targets
        ):
            continue
        value = statement.value
        if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return None
        names = {
            item.value
            for item in value.elts
            if isinstance(item, ast.Constant)
            and isinstance(item.value, str)
        }
        return frozenset(names) if len(names) == len(value.elts) else None
    if any(
        isinstance(node, ast.Call)
        and _call_name(node.func).casefold()
        in _PYTHON_DYNAMIC_BINDING_CALLS
        for node in ast.walk(tree)
    ):
        return None
    exports: set[str] = set()
    for statement in body:
        if isinstance(
            statement,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            exports.add(statement.name)
        elif isinstance(statement, ast.Import):
            exports.update(
                alias.asname or alias.name.split(".", 1)[0]
                for alias in statement.names
            )
        elif isinstance(statement, ast.ImportFrom):
            if any(alias.name == "*" for alias in statement.names):
                return None
            exports.update(alias.asname or alias.name for alias in statement.names)
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                exports.update(_target_names(target))
    return frozenset(name for name in exports if not name.startswith("_"))


class _JsTsTaintVisitor:
    def __init__(self, ids: IdFactory, flow: FlowMap, path: Path, lines: list[str], max_edges: int, max_findings_per_rule: int, function_summaries: dict[str, JsTsFunctionSummary]) -> None:
        self.ids = ids
        self.flow = flow
        self.path = path
        self.lines = lines
        self.analysis_lines = _strip_js_ts_comments(lines)
        self.command_bindings = _js_ts_command_bindings("\n".join(self.analysis_lines))
        self.max_edges = max_edges
        self.max_findings_per_rule = max_findings_per_rule
        self.function_summaries = function_summaries
        self.scope_ids, self.scope_parents, self.scope_analysis_limited = _js_ts_function_scopes(
            self.analysis_lines
        )
        self.taints: dict[int, dict[str, TaintSource]] = {0: {}}
        self.bindings: dict[int, set[str]] = {0: set()}
        self.node_counter = 0
        self.edge_count = 0
        self.finding_counts: dict[str, int] = {}
        self.node_ids: dict[tuple[str, int, str], str] = {}
        self.edge_seen: set[tuple[str, str, str]] = set()
        self.finding_seen: set[tuple[str, str, int, int]] = set()
        self.limit_findings: set[str] = set()
        self.line_hashes: dict[str, str] = {}

    def visit(self) -> None:
        if self.scope_analysis_limited:
            self._append_limit_finding("function_scope_marker_limit", 1)
        for line_no, line in enumerate(self.analysis_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            scope_id = self.scope_ids[line_no - 1]
            self.taints.setdefault(scope_id, {})
            self.bindings.setdefault(scope_id, set())
            lower = stripped.lower()
            declared_params = _js_ts_declared_params(stripped)
            if declared_params:
                request_params = set(_js_ts_request_params(stripped))
                for param in declared_params:
                    self.bindings[scope_id].add(param)
                    if param in request_params:
                        self.taints[scope_id][param] = self._source(
                            "request_arg",
                            param,
                            line_no,
                            sensitive=_request_parameter_is_sensitive(param),
                        )
            if "=" in stripped:
                assignment = _js_ts_assignment(stripped)
                if assignment:
                    targets, expression = assignment
                    source = self._expr_source(expression, line_no, scope_id)
                    declaration = bool(re.search(r"\b(?:const|let|var)\b", stripped))
                    for name in targets:
                        if declaration:
                            self.bindings[scope_id].add(name)
                        if source:
                            self.taints[scope_id][name] = source if source.sensitive or not SENSITIVE_NAME.search(name) else self._source(source.kind, name, line_no, sensitive=True)
                        else:
                            self.taints[scope_id].pop(name, None)
            sink_kind = (
                _js_ts_sink_kind(
                    stripped,
                    self.command_bindings,
                    line_no,
                    len(line) - len(line.lstrip()),
                )
                if _might_have_js_ts_sink(lower)
                else None
            )
            if not sink_kind:
                continue
            sink_expression = _js_ts_sink_relevant_expression(stripped, sink_kind)
            for source in self._tainted_sources(sink_expression, line_no, scope_id):
                if not _js_ts_source_relevant_for_sink(source, sink_kind):
                    continue
                self._append_taint_edge(source, sink_kind, line_no)
        self._append_multiline_statement_findings()
        self._append_framework_findings()

    def _append_multiline_statement_findings(self) -> None:
        statement_taints: dict[int, dict[str, tuple[TaintSource, bool]]] = {0: {}}
        statement_bindings: dict[int, set[str]] = {0: set()}
        pending = deque(_js_ts_logical_statements(self.analysis_lines))
        processed_statements = 0
        while pending:
            processed_statements += 1
            if processed_statements > JS_TS_LOGICAL_STATEMENT_LIMIT:
                self._append_limit_finding("logical_statement_expansion_limit", 1)
                break
            start, end, rendered = pending.popleft()
            declared_params = _js_ts_declared_params(rendered)
            fragment_text = "\n".join(self.analysis_lines[start - 1 : end])
            body_open = _js_ts_function_body_open(fragment_text)
            wraps_function_body = (
                end > start
                and bool(declared_params)
                and body_open >= 0
            )
            statement_scopes = set(self.scope_ids[max(0, start - 1) : end]) if self.scope_ids else {0}
            if len(statement_scopes) != 1:
                continue
            scope_id = next(iter(statement_scopes))
            statement_taints.setdefault(scope_id, {})
            statement_bindings.setdefault(scope_id, set())
            for param in declared_params:
                statement_bindings[scope_id].add(param)
                if _looks_like_request_name(param):
                    statement_taints[scope_id][param] = (
                        self._source(
                            "request_arg",
                            param,
                            start,
                            sensitive=_request_parameter_is_sensitive(param),
                        ),
                        end > start,
                    )
            if wraps_function_body:
                braced = _extract_braced_body(
                    fragment_text,
                    body_open,
                    max_chars=len(fragment_text) + 1,
                )
                inner = braced[1:-1] if braced.endswith("}") else braced[1:]
                body_line_offset = fragment_text[: body_open + 1].count("\n")
                nested = [
                    (
                        start + body_line_offset + nested_start - 1,
                        start + body_line_offset + nested_end - 1,
                        nested_rendered,
                    )
                    for nested_start, nested_end, nested_rendered in _js_ts_logical_statements(
                        inner.splitlines()
                    )
                ]
                pending.extendleft(reversed(nested))
                continue
            assignment = _js_ts_assignment(rendered)
            if assignment:
                targets, expression = assignment
                source: TaintSource | None = None
                source_was_multiline = end > start
                for name in _js_ts_names(_js_ts_code_without_literals(expression)):
                    inherited = _js_ts_statement_taint_lookup(
                        statement_taints,
                        statement_bindings,
                        self.scope_parents,
                        scope_id,
                        name,
                    )
                    if inherited is not None:
                        source, inherited_multiline = inherited
                        source_was_multiline = source_was_multiline or inherited_multiline
                        break
                if source is None:
                    source_kind = _js_ts_source_kind(_js_ts_code_without_literals(expression))
                    if source_kind:
                        source = self._source(
                            source_kind,
                            expression,
                            start,
                            sensitive=_js_ts_source_is_sensitive(source_kind, expression),
                        )
                declaration = bool(re.search(r"\b(?:const|let|var)\b", rendered))
                for target in targets:
                    if declaration:
                        statement_bindings[scope_id].add(target)
                    if source is None:
                        statement_taints[scope_id].pop(target, None)
                    else:
                        statement_taints[scope_id][target] = (source, source_was_multiline)

            sink_kind = _js_ts_sink_kind(rendered, self.command_bindings, end)
            if sink_kind is None:
                continue
            sink_expression = _js_ts_sink_relevant_expression(rendered, sink_kind)
            emitted = False
            for name in _js_ts_names(_js_ts_code_without_literals(sink_expression)):
                inherited = _js_ts_statement_taint_lookup(
                    statement_taints,
                    statement_bindings,
                    self.scope_parents,
                    scope_id,
                    name,
                )
                if inherited is None:
                    continue
                source, source_was_multiline = inherited
                if not source.sensitive and _js_ts_reference_is_sensitive(sink_expression, name):
                    source = TaintSource(
                        kind=source.kind,
                        name=source.name,
                        line=source.line,
                        line_hash=source.line_hash,
                        sensitive=True,
                        projection=source.projection,
                    )
                if _js_ts_source_relevant_for_sink(source, sink_kind) and (
                    end > start or source_was_multiline
                ):
                    self._append_taint_edge(source, sink_kind, end)
                    emitted = True
                    break
            if emitted:
                continue
            for source_line in range(start, end + 1):
                source_expression = _js_ts_code_without_literals(
                    self.analysis_lines[source_line - 1]
                )
                source_kind = _js_ts_source_kind(source_expression)
                if source_kind is None:
                    continue
                if source_kind == "db_read" and sink_kind == "sql":
                    continue
                source = self._source(
                    source_kind,
                    source_expression,
                    source_line,
                    sensitive=_js_ts_source_is_sensitive(source_kind, source_expression),
                )
                if _js_ts_source_relevant_for_sink(source, sink_kind):
                    self._append_taint_edge(source, sink_kind, end)
                    break

    def _append_framework_findings(self) -> None:
        text = "\n".join(self.analysis_lines)
        lower = text.lower()
        untrusted_auth_helpers = _js_ts_local_untrusted_auth_helpers(text)
        handler_scopes = _js_ts_route_handler_scopes(self.path, text)
        next_scopes = [scope for scope in handler_scopes if scope.kind == "next_route"]
        weak_next_scope = next(
            (
                scope
                for scope in next_scopes
                if _js_ts_has_data_or_response(scope.rendered.lower())
                and not _js_ts_has_effective_auth_guard(scope.rendered.lower(), untrusted_auth_helpers)
            ),
            None,
        )
        if not next_scopes and _js_ts_has_next_route_surface(self.path, lower) and _js_ts_has_data_or_response(lower) and not _js_ts_has_effective_auth_guard(lower, untrusted_auth_helpers):
            weak_next_scope = JsTsHandlerScope("next_route", text, 1)
        if weak_next_scope is not None:
            self._append_framework_finding(
                "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK",
                "Next.js route handler returns data without an obvious auth boundary",
                "next_route_auth_boundary",
                _js_ts_scope_first_line(
                    weak_next_scope,
                    ("nextresponse.json", "response.json", "return response", "return nextresponse", "return json"),
                ),
                "Route handlers that read request, params, cookies, or data stores should prove who can access the returned fields.",
                "Add an explicit auth/session check before reading user-scoped data or returning JSON, and verify object ownership before response construction.",
            )
        action_scopes = _js_ts_exported_function_scopes(text) if _js_ts_has_server_action(lower) else []
        weak_action_scope = next(
            (
                scope
                for scope in action_scopes
                if _js_ts_has_mutation(scope.rendered.lower())
                and not _js_ts_has_effective_auth_guard(scope.rendered.lower(), untrusted_auth_helpers)
            ),
            None,
        )
        if not action_scopes and _js_ts_has_server_action(lower) and _js_ts_has_mutation(lower) and not _js_ts_has_effective_auth_guard(lower, untrusted_auth_helpers):
            weak_action_scope = JsTsHandlerScope("server_action", text, 1)
        if weak_action_scope is not None:
            self._append_framework_finding(
                "JS_TS_NEXT_SERVER_ACTION_AUTH_BOUNDARY_WEAK",
                "Next.js server action mutates data without an obvious auth boundary",
                "next_server_action_auth_boundary",
                _js_ts_scope_first_line(weak_action_scope, (".insert(", ".update(", ".delete(", ".create(", ".set(", ".save(")),
                "Server actions can be invoked from client flows; mutations need a user/session check and ownership constraints.",
                "Check the authenticated user at the top of the action and include owner/user constraints in the write.",
            )
        express_scopes = [scope for scope in handler_scopes if scope.kind == "express_route"]
        weak_express_scope = next(
            (
                scope
                for scope in express_scopes
                if _js_ts_reads_param_id(scope.rendered.lower())
                and not _js_ts_has_effective_ownership_check(scope.rendered.lower(), untrusted_auth_helpers)
                and not _js_ts_express_detail_has_equivalent_collection_peer(text, scope)
            ),
            None,
        )
        if not express_scopes and _js_ts_has_express_id_route(lower) and _js_ts_reads_param_id(lower) and not _js_ts_has_effective_ownership_check(lower, untrusted_auth_helpers):
            weak_express_scope = JsTsHandlerScope("express_route", text, 1)
        if weak_express_scope is not None:
            self._append_framework_finding(
                "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "Express route reads an id parameter without an obvious ownership check",
                "express_idor_route_param",
                _js_ts_scope_first_line(weak_express_scope, ("req.params", "params.id", ".findunique", ".findfirst", ".findbyid")),
                "Route parameters such as :id often become IDOR/BOLA bugs when the handler fetches by id but does not constrain by the authenticated owner.",
                "Require authentication and include owner/user/team scope in the query before returning or mutating the object.",
            )
        if "supabase" in lower and "service_role" in lower and _js_ts_has_route_or_action_surface(self.path, lower):
            self._append_framework_finding(
                "JS_TS_SUPABASE_SERVICE_ROLE_IN_ROUTE",
                "Supabase service-role key appears in a request-facing route",
                "supabase_service_role_boundary",
                _first_line_matching(self.analysis_lines, ("service_role", "supabase_service_role", "createsupabaseclient", "createclient")),
                "Service-role Supabase clients bypass row-level policies and should not be reachable from request-handling code.",
                "Move service-role operations behind a narrow server-only job/admin boundary, or use user-scoped clients plus RLS policies.",
            )
        request_scopes = [
            _js_ts_expand_scope_with_local_callees(scope, text)
            for scope in [*handler_scopes, *action_scopes]
        ]
        weak_supabase_scope = next(
            (
                scope
                for scope in request_scopes
                if ".from(" in scope.rendered.casefold()
                and not _js_ts_has_effective_auth_guard(scope.rendered.casefold(), untrusted_auth_helpers)
                and not _js_ts_mentions_rls(scope.rendered.casefold())
            ),
            None,
        )
        if (
            weak_supabase_scope is None
            and not request_scopes
            and "supabase" in lower
            and ".from(" in lower
            and _js_ts_has_route_or_action_surface(self.path, lower)
            and not _js_ts_has_effective_auth_guard(lower, untrusted_auth_helpers)
            and not _js_ts_mentions_rls(lower)
        ):
            weak_supabase_scope = JsTsHandlerScope("request_surface", text, 1)
        if "supabase" in lower and weak_supabase_scope is not None:
            self._append_framework_finding(
                "JS_TS_SUPABASE_RLS_AUTH_BOUNDARY_WEAK",
                "Supabase query lacks an obvious auth/RLS boundary",
                "supabase_rls_auth_boundary",
                _js_ts_scope_first_line(weak_supabase_scope, (".from(", ".select(", ".insert(", ".update(", ".delete(")),
                "Supabase data access depends on user-scoped clients and RLS; request-facing queries without an auth hint deserve review.",
                "Use a user session scoped Supabase client, verify RLS is enabled for the table, and constrain reads/writes by the authenticated user.",
            )
        firebase_surface = "firebase-admin" in lower or "admin.firestore" in lower or "getfirestore(" in lower
        weak_firebase_scope = next(
            (
                scope
                for scope in request_scopes
                if _js_ts_has_firebase_admin_access(scope.rendered.casefold())
                and not _js_ts_has_effective_auth_guard(scope.rendered.casefold(), untrusted_auth_helpers)
            ),
            None,
        )
        if (
            weak_firebase_scope is None
            and not request_scopes
            and firebase_surface
            and _js_ts_has_firebase_admin_access(lower)
            and not _js_ts_has_effective_auth_guard(lower, untrusted_auth_helpers)
        ):
            weak_firebase_scope = JsTsHandlerScope("request_surface", text, 1)
        if firebase_surface and weak_firebase_scope is not None:
            self._append_framework_finding(
                "JS_TS_FIREBASE_ADMIN_AUTH_BOUNDARY_WEAK",
                "Firebase Admin data access lacks an obvious auth boundary",
                "firebase_admin_auth_boundary",
                _js_ts_scope_first_line(weak_firebase_scope, ("admin.firestore", "getfirestore", ".doc(", "req.params", "params.id")),
                "Firebase Admin SDK bypasses client security rules, so document reads, collection listings, and writes need a server-side auth boundary.",
                "Authenticate the caller, constrain collection queries, and verify document ownership before reading or writing with the Admin SDK.",
            )
        self._append_interprocedural_findings(text, lower)

    def _append_interprocedural_findings(self, text: str, lower: str) -> None:
        if not self.function_summaries or not _js_ts_has_route_or_action_surface(self.path, lower):
            return
        if not _js_ts_has_request_id_access(lower) or _js_ts_has_ownership_check(lower):
            return
        request_derived = _js_ts_request_derived_names(text)
        for summary in sorted(self.function_summaries.values(), key=lambda item: (item.file, item.line, item.name)):
            if summary.file == str(self.path):
                continue
            call = re.search(rf"\b{re.escape(summary.name)}\s*\(", text)
            if call is None:
                continue
            arguments = _js_ts_parenthesized_content(text, call.end() - 1)
            argument_code = _js_ts_code_without_literals(arguments)
            if not _js_ts_source_kind(argument_code) and not any(
                re.search(rf"\b{re.escape(name)}\b", argument_code) for name in request_derived
            ):
                continue
            line = _first_line_matching(self.analysis_lines, (f"{summary.name}(",))
            self._append_interprocedural_finding(summary, line)
            return

    def _append_interprocedural_finding(self, summary: JsTsFunctionSummary, line: int) -> None:
        rule_id = "JS_TS_INTERPROCEDURAL_ROUTE_SERVICE_IDOR"
        if self.finding_counts.get(rule_id, 0) >= 1:
            return
        self.finding_counts[rule_id] = 1
        line = max(1, min(line, len(self.lines) or 1))
        route_node = self._node_id("source", "js/ts route request id", line)
        service_node = f"S{len(self.flow.nodes) + 1}"
        self.flow.nodes.append(FlowNode(service_node, "sink", "js/ts service data read", summary.file, summary.line))
        self.flow.edges.append(FlowEdge(route_node, service_node, "js/ts limited inter-procedural call"))
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="js-ts-framework",
                rule_id=rule_id,
                severity="high",
                confidence="medium",
                title="Route passes request id into a data service without an obvious ownership boundary",
                file=str(self.path),
                line_start=line,
                line_end=line,
                evidence=(
                    "detector_subtype=js_ts_limited_interprocedural_route_service "
                    f"route_call_hash={_line_hash(self.lines, line, self.line_hashes)} service_name_hash={evidence_hash(summary.name)} "
                    f"service_line_hash={summary.line_hash} data_access={summary.data_access}"
                ),
                why_it_matters="A route that forwards a request-controlled id into a helper/service data read can become IDOR/BOLA when ownership is checked neither in the route nor in the service.",
                recommendation="Require authentication at the route boundary and include owner/user/tenant scope in the service query before returning the object.",
                audit_depth=4,
                inspected_scope="Project-level JS/TS pass summarized exported service/helper functions and matched route calls by identifier and raw-free line hashes.",
                not_inspected="This is a limited regex-level inter-procedural pass; it does not fully resolve TypeScript types, aliases, dependency injection, middleware auth, generated clients, or deployed database policies.",
            )
        )

    def _append_framework_finding(
        self,
        rule_id: str,
        title: str,
        subtype: str,
        line: int,
        why: str,
        recommendation: str,
        *,
        severity: str = "high",
        confidence: str = "medium",
    ) -> None:
        if self.finding_counts.get(rule_id, 0) >= 1:
            return
        self.finding_counts[rule_id] = 1
        line = max(1, min(line, len(self.lines) or 1))
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="js-ts-framework",
                rule_id=rule_id,
                severity=severity,
                confidence=confidence,
                title=title,
                file=str(self.path),
                line_start=line,
                line_end=line,
                evidence=f"detector_subtype={subtype} line_hash={_line_hash(self.lines, line, self.line_hashes)}",
                why_it_matters=why,
                recommendation=recommendation,
                audit_depth=4,
                inspected_scope="JS/TS framework-aware heuristic reviewed route/action shape, data access, and auth-boundary hints without storing raw values.",
                not_inspected="This heuristic does not execute the app, resolve imports fully, inspect deployed RLS/Firebase rules, or prove authorization correctness.",
            )
        )

    def _expr_source(self, expression: str, line_no: int, scope_id: int) -> TaintSource | None:
        executable = _js_ts_code_without_literals(expression)
        for name in _js_ts_names(executable):
            source = self._lookup_taint(scope_id, name)
            if source is not None:
                return source
        source_kind = _js_ts_source_kind(executable)
        if source_kind:
            return self._source(
                source_kind,
                executable,
                line_no,
                sensitive=_js_ts_source_is_sensitive(source_kind, executable),
            )
        return None

    def _tainted_sources(self, line: str, line_no: int, scope_id: int) -> list[TaintSource]:
        found: list[TaintSource] = []
        seen: set[tuple[str, int, str]] = set()
        executable = _js_ts_code_without_literals(line)
        for name in _js_ts_names(executable):
            source = self._lookup_taint(scope_id, name)
            if source is None:
                continue
            if not source.sensitive and _js_ts_reference_is_sensitive(executable, name):
                source = TaintSource(
                    kind=source.kind,
                    name=source.name,
                    line=source.line,
                    line_hash=source.line_hash,
                    sensitive=True,
                    projection=source.projection,
                )
            key = (source.kind, source.line, source.name)
            if key not in seen:
                seen.add(key)
                found.append(source)
        direct_kind = _js_ts_source_kind(executable)
        if direct_kind:
            direct = self._source(
                direct_kind,
                executable,
                line_no,
                sensitive=_js_ts_source_is_sensitive(direct_kind, executable),
            )
            key = (direct.kind, direct.line, direct.name)
            if key not in seen:
                found.append(direct)
        return found

    def _lookup_taint(self, scope_id: int, name: str) -> TaintSource | None:
        current: int | None = scope_id
        while current is not None:
            if name in self.bindings.get(current, set()):
                return self.taints.get(current, {}).get(name)
            current = self.scope_parents.get(current)
        return None

    def _source(self, kind: str, name: str, line: int, sensitive: bool) -> TaintSource:
        return TaintSource(kind=kind, name=_safe_label(name), line=line, line_hash=_line_hash(self.lines, line, self.line_hashes), sensitive=sensitive)

    def _append_taint_edge(self, source: TaintSource, sink_kind: str, sink_line: int) -> None:
        rule_id = _js_ts_rule_id_for_sink(sink_kind)
        finding_key = (rule_id, source.kind, source.line, sink_line)
        if finding_key in self.finding_seen:
            return
        if self.edge_count >= self.max_edges:
            self._append_limit_finding("edge_limit", sink_line)
            return
        if self.finding_counts.get(rule_id, 0) >= self.max_findings_per_rule:
            self._append_limit_finding(f"finding_limit:{rule_id}", sink_line)
            return
        self.finding_seen.add(finding_key)
        source_id = self._node_id("source", f"js/ts {source.kind}", source.line)
        sink_id = self._node_id("sink", f"js/ts {sink_kind}", sink_line)
        label = "js/ts intra-file taint"
        edge_key = (source_id, sink_id, label)
        if edge_key not in self.edge_seen:
            self.edge_seen.add(edge_key)
            self.flow.edges.append(FlowEdge(source_id, sink_id, label))
            self.edge_count += 1
        self.finding_counts[rule_id] = self.finding_counts.get(rule_id, 0) + 1
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="js-ts-taint",
                rule_id=rule_id,
                severity=_severity_for_sink(sink_kind),
                confidence="medium" if source.sensitive else "low",
                title=_js_ts_title_for_sink(sink_kind),
                file=str(self.path),
                line_start=sink_line,
                line_end=sink_line,
                evidence=(
                    f"js_ts_source={source.kind} source_line={source.line} sink={sink_kind} sink_line={sink_line}; "
                    f"source_hash={source.line_hash} sink_hash={_line_hash(self.lines, sink_line, self.line_hashes)}"
                ),
                why_it_matters=_why_for_sink(sink_kind),
                recommendation=_recommendation_for_sink(sink_kind),
                audit_depth=4,
                inspected_scope="JS/TS intra-file taint linked a request/DB/env source to this sink without storing raw values.",
                not_inspected="This bounded analyzer handles direct and multi-line intra-file assignments plus limited route/service summaries; it does not parse a full TypeScript AST, resolve imports or dependency injection, model arbitrary control flow, or prove runtime reachability.",
            )
        )

    def _append_limit_finding(self, limit_kind: str, line: int) -> None:
        if limit_kind in self.limit_findings:
            return
        self.limit_findings.add(limit_kind)
        line = max(1, min(line, len(self.lines) or 1))
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="js-ts-taint",
                rule_id="STATIC_ANALYSIS_LIMIT_REACHED",
                severity="high",
                confidence="high",
                title="JS/TS flow analysis reached a bounded coverage limit",
                file=str(self.path),
                line_start=line,
                line_end=line,
                evidence=(
                    f"detector_subtype=js_ts_taint_coverage_limit limit_ref={evidence_hash(limit_kind)} "
                    f"max_edges={self.max_edges} max_findings_per_rule={self.max_findings_per_rule} raw_returned=false"
                ),
                why_it_matters="A release gate cannot claim complete static flow coverage after candidate flows were truncated.",
                recommendation="Split the file, raise the reviewed analyzer bounds, or run the deep analyzer and repeat the release review until no coverage limit is reached.",
                audit_depth=4,
                inspected_scope="The analyzer recorded that an additional candidate flow existed beyond its configured per-file bound.",
                not_inspected="Candidate flows after the reported bound were not enumerated; this finding intentionally fails closed.",
            )
        )

    def _node_id(self, kind: str, label: str, line: int) -> str:
        key = (kind, line, label)
        if key in self.node_ids:
            return self.node_ids[key]
        self.node_counter += 1
        node_id = f"J{len(self.flow.nodes) + self.node_counter}"
        self.node_ids[key] = node_id
        self.flow.nodes.append(FlowNode(node_id, kind, label, str(self.path), line))
        return node_id


class _PythonTaintVisitor(ast.NodeVisitor):
    def __init__(
        self,
        ids: IdFactory,
        flow: FlowMap,
        path: Path,
        lines: list[str],
        *,
        default_log_threshold: int | None = None,
        logger_thresholds: dict[str, int | None] | None = None,
    ) -> None:
        self.ids = ids
        self.flow = flow
        self.path = path
        self.lines = lines
        self.default_log_threshold = default_log_threshold
        self.logger_thresholds = logger_thresholds or {}
        self.taints: dict[str, TaintSource] = {}
        self.node_counter = 0
        self.node_ids: dict[tuple[str, int, str], str] = {}
        self.edge_seen: set[tuple[str, str, str]] = set()
        self.finding_seen: set[tuple[str, str, int]] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:  # noqa: N802
        previous = self.taints
        self.taints = {}
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if _looks_like_request_name(arg.arg) or (node.name.startswith("resolve_") and arg.arg not in {"self", "root", "info"}):
                self.taints[arg.arg] = self._source("request_arg", arg.arg, node.lineno, sensitive=True)
        self.generic_visit(node)
        self.taints = previous

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:  # noqa: N802
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Assign(self, node: ast.Assign) -> Any:  # noqa: N802
        source = self._expr_source(node.value)
        for target in node.targets:
            for name in _target_names(target):
                if source:
                    self.taints[name] = self._source_for_assignment(source, name, node.lineno)
                else:
                    self.taints.pop(name, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:  # noqa: N802
        if node.value is not None:
            source = self._expr_source(node.value)
            for name in _target_names(node.target):
                if source:
                    self.taints[name] = self._source_for_assignment(source, name, node.lineno)
                else:
                    self.taints.pop(name, None)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:  # noqa: N802
        sink_kind = _sink_kind(node)
        if sink_kind:
            if sink_kind == "log" and self._log_call_is_inactive(node):
                sink_kind = "dormant_log"
            sources = [
                source
                for source in self._tainted_sources(node)
                if source.sensitive or sink_kind in {"llm_call", "mcp_tool_call", "external_http"}
            ]
            strongest = max(sources, key=_source_exposure_rank, default=None)
            for source in sources:
                self._append_taint_edge(source, sink_kind, node.lineno, emit_finding=source is strongest)
        self.generic_visit(node)

    def _log_call_is_inactive(self, node: ast.Call) -> bool:
        name = _call_name(node.func).lower()
        level_name = name.rsplit(".", 1)[-1]
        call_level = PYTHON_LOG_LEVELS.get(level_name)
        if call_level is None:
            return False
        logger_name = name.split(".", 1)[0]
        threshold = self._log_threshold(logger_name)
        return threshold is not None and call_level < threshold

    def _log_threshold(self, logger_name: str) -> int | None:
        if logger_name in self.logger_thresholds:
            return self.logger_thresholds[logger_name]
        return self.default_log_threshold

    def visit_Return(self, node: ast.Return) -> Any:  # noqa: N802
        if node.value is not None:
            sources = [source for source in self._tainted_sources(node.value) if source.sensitive]
            strongest = max(sources, key=_source_exposure_rank, default=None)
            for source in sources:
                self._append_taint_edge(source, "response", node.lineno, emit_finding=source is strongest)
        self.generic_visit(node)

    def _expr_source(self, node: ast.AST) -> TaintSource | None:
        if _is_non_sensitive_projection(node):
            return None
        field_source = self._request_field_source(node)
        if field_source:
            return field_source
        if isinstance(node, ast.Name) and node.id in self.taints:
            return self.taints[node.id]
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.taints:
                return self.taints[child.id]
        source_kind = _source_kind(node)
        if source_kind:
            text = _node_text(node)
            return self._source(source_kind, text, getattr(node, "lineno", 1), sensitive=bool(SENSITIVE_NAME.search(text)) or source_kind in {"request_body", "db_read"})
        return None

    def _request_field_source(self, node: ast.AST) -> TaintSource | None:
        for candidate in ast.walk(node):
            container_name: str | None = None
            field_name: str | None = None
            if isinstance(candidate, ast.Subscript):
                container_name = _attribute_root_name(candidate.value)
                if isinstance(candidate.slice, ast.Constant) and isinstance(candidate.slice.value, str):
                    field_name = candidate.slice.value
            elif (
                isinstance(candidate, ast.Call)
                and isinstance(candidate.func, ast.Attribute)
                and candidate.func.attr == "get"
                and candidate.args
                and isinstance(candidate.args[0], ast.Constant)
                and isinstance(candidate.args[0].value, str)
            ):
                container_name = _attribute_root_name(candidate.func.value)
                field_name = candidate.args[0].value
            source = self.taints.get(container_name or "")
            if source is not None and source.kind in {"request_arg", "request_body"} and field_name:
                return self._source(
                    "request_body",
                    field_name,
                    getattr(candidate, "lineno", source.line),
                    sensitive=_field_is_sensitive(field_name),
                )
        return None

    def _source_for_assignment(self, source: TaintSource, name: str, line: int) -> TaintSource:
        if _is_operational_metadata_name(name):
            return self._source(source.kind, name, line, sensitive=False)
        if source.sensitive or not _field_is_sensitive(name):
            return source
        return self._source(source.kind, name, line, sensitive=True)

    def _tainted_sources(self, node: ast.AST) -> list[TaintSource]:
        found: list[TaintSource] = []
        seen: set[tuple[str, int, str, str]] = set()

        def collect(expression: ast.AST) -> None:
            if _is_non_sensitive_projection(expression):
                return
            field_source = self._request_field_source(expression)
            if field_source is not None:
                key = (field_source.kind, field_source.line, field_source.name, field_source.projection)
                if key not in seen:
                    seen.add(key)
                    found.append(field_source)
                return
            projected = self._bounded_prefix_source(expression)
            if projected:
                key = (projected.kind, projected.line, projected.name, projected.projection)
                if key not in seen:
                    seen.add(key)
                    found.append(projected)
                return
            if isinstance(expression, ast.Name) and expression.id in self.taints:
                source = self.taints[expression.id]
                key = (source.kind, source.line, source.name, source.projection)
                if key not in seen:
                    seen.add(key)
                    found.append(source)
                return
            if isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript)):
                source_kind = _source_kind(expression)
                if source_kind:
                    text = _node_text(expression)
                    source = self._source(
                        source_kind,
                        text,
                        getattr(expression, "lineno", 1),
                        sensitive=bool(SENSITIVE_NAME.search(text)) or source_kind in {"request_body", "db_read"},
                    )
                    key = (source.kind, source.line, source.name, source.projection)
                    if key not in seen:
                        seen.add(key)
                        found.append(source)
                    return
            for child in ast.iter_child_nodes(expression):
                collect(child)

        roots: list[ast.AST]
        if isinstance(node, ast.Call):
            roots = [*node.args, *(keyword.value for keyword in node.keywords)]
        else:
            roots = [node]
        for root in roots:
            collect(root)
        return found

    def _bounded_prefix_source(self, node: ast.AST) -> TaintSource | None:
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name):
            return None
        source = self.taints.get(node.value.id)
        if source is None or not source.sensitive or not _is_bounded_prefix_slice(node.slice):
            return None
        return TaintSource(
            kind=source.kind,
            name=source.name,
            line=source.line,
            line_hash=source.line_hash,
            sensitive=True,
            projection="bounded_prefix",
        )

    def _source(self, kind: str, name: str, line: int, sensitive: bool) -> TaintSource:
        return TaintSource(kind=kind, name=_safe_label(name), line=line, line_hash=_line_hash(self.lines, line), sensitive=sensitive)

    def _append_taint_edge(self, source: TaintSource, sink_kind: str, sink_line: int, *, emit_finding: bool = True) -> None:
        source_id = self._node_id("source", f"ast {source.kind}", source.line)
        sink_id = self._node_id("sink", f"ast {sink_kind}", sink_line)
        label = "python AST taint"
        edge_key = (source_id, sink_id, label)
        if edge_key not in self.edge_seen:
            self.edge_seen.add(edge_key)
            self.flow.edges.append(FlowEdge(source_id, sink_id, label))
        if not emit_finding:
            return
        finding_key = (_rule_id_for_sink(sink_kind), str(self.path), sink_line)
        if finding_key in self.finding_seen:
            return
        self.finding_seen.add(finding_key)
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="ast-taint",
                rule_id=_rule_id_for_sink(sink_kind),
                severity="medium" if sink_kind == "log" and source.projection == "bounded_prefix" else _severity_for_sink(sink_kind),
                confidence="medium" if source.sensitive else "low",
                title=_title_for_sink(sink_kind),
                file=str(self.path),
                line_start=sink_line,
                line_end=sink_line,
                evidence=self._taint_evidence(source, sink_kind, sink_line),
                why_it_matters=_why_for_sink(sink_kind),
                recommendation=_recommendation_for_sink(sink_kind),
                audit_depth=5,
                inspected_scope="Python AST intra-procedural taint analysis linked a request/DB/env source to this sink without storing raw values.",
                not_inspected="This does not prove runtime reachability, authorization state, branch conditions, or values inside external services.",
            )
        )

    def _taint_evidence(self, source: TaintSource, sink_kind: str, sink_line: int) -> str:
        logging_context = ""
        if sink_kind == "dormant_log":
            call_name = ""
            if 0 < sink_line <= len(self.lines):
                match = re.search(
                    r"\b(logging|[A-Za-z_][A-Za-z0-9_]*)\."
                    r"(?:debug|info|warning|warn|error|exception|critical)\s*\(",
                    self.lines[sink_line - 1],
                    re.IGNORECASE,
                )
                call_name = match.group(1).lower() if match else ""
            threshold = self._log_threshold(call_name)
            if threshold is not None:
                logging_context = f" effective_log_threshold={PYTHON_LOG_LEVEL_NAMES.get(threshold, threshold)}"
        return (
            f"python_ast_source={source.kind} source_line={source.line} projection={source.projection} "
            f"sink={sink_kind} sink_line={sink_line}{logging_context}; "
            f"source_hash={source.line_hash} sink_hash={_line_hash(self.lines, sink_line)}"
        )

    def _node_id(self, kind: str, label: str, line: int) -> str:
        key = (kind, line, label)
        if key in self.node_ids:
            return self.node_ids[key]
        self.node_counter += 1
        node_id = f"A{len(self.flow.nodes) + self.node_counter}"
        self.node_ids[key] = node_id
        self.flow.nodes.append(FlowNode(node_id, kind, label, str(self.path), line))
        return node_id


class _PythonSecurityTaintAnalyzer:
    _SOURCE_METHODS = (
        "get_form_parameter",
        "get_query_parameter",
        "get_header",
        "get_cookie",
        "get_parameter",
        "get_json",
    )
    def __init__(
        self,
        ids: IdFactory,
        flow: FlowMap,
        path: Path,
        lines: list[str],
        function_summaries: dict[str, PythonFunctionSummary],
        same_file_request_backfills: frozenset[str],
        html_sanitizer_files: dict[str, str],
        local_python_modules: set[str],
        sink_summaries: dict[str, list[PythonSinkSummary]],
        weak_prefix_guard_summaries: dict[
            str,
            list[PythonWeakPrefixGuardSummary],
        ],
    ) -> None:
        self.ids = ids
        self.flow = flow
        self.path = path
        self.lines = lines
        self.env: dict[str, PythonSecurityValue] = {}
        self.lists: dict[str, list[PythonSecurityValue]] = {}
        self.maps: dict[str, dict[object, PythonSecurityValue]] = {}
        self.finding_keys: set[tuple[str, int]] = set()
        self.node_ids: dict[tuple[str, int, str], str] = {}
        self.node_counter = 0
        self.function_summaries = function_summaries
        self.same_file_request_backfills = same_file_request_backfills
        self.html_sanitizer_files = html_sanitizer_files
        self.local_python_modules = frozenset(local_python_modules)
        self.available_html_sanitizer_dependencies = frozenset(
            html_sanitizer_files
        ).union(
            sanitizer
            for sanitizer in _PYTHON_STANDARD_HTML_SANITIZERS
            if sanitizer.split(".", 1)[0] not in self.local_python_modules
        )
        self.sink_summaries = sink_summaries
        self.weak_prefix_guard_summaries = weak_prefix_guard_summaries
        self.imported_functions: dict[str, tuple[str, str]] = {}
        self.imported_modules: dict[str, str] = {}
        self.tree: ast.AST | None = None
        self.current_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        self.enclosing_function_scopes: list[
            ast.FunctionDef | ast.AsyncFunctionDef
        ] = []
        self.function_parent_scopes: dict[
            ast.FunctionDef | ast.AsyncFunctionDef,
            ast.AST,
        ] = {}
        self.function_parent_scopes_ready = False
        self.call_binding_cache: dict[
            tuple[int, str, str | None, bool, bool],
            bool,
        ] = {}
        self.module_binding_resolution_nodes: list[ast.AST] = []
        self.definition_header_binding_cache: dict[
            tuple[int, str],
            bool,
        ] = {}
        self.active_command_guard_source_lines: list[frozenset[int]] = []
        self.active_command_guard_names: list[frozenset[str]] = []
        self.post_command_guard_source_lines: set[int] = set()
        self.active_weak_prefix_command_guards: list[
            frozenset[tuple[int, str]]
        ] = []

    def analyze(self, tree: ast.AST) -> None:
        self.tree = tree
        self.enclosing_function_scopes = []
        self.function_parent_scopes = {}
        self.function_parent_scopes_ready = False
        self.module_binding_resolution_nodes = _python_nodes_in_lexical_scope(
            tree
        )
        self._collect_import_bindings(tree)
        body = getattr(tree, "body", [])
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(statement)
            elif isinstance(statement, ast.ClassDef):
                for child in statement.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function(child)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        previous = self._snapshot()
        previous_function = self.current_function
        previous_active_command_guards = self.active_command_guard_source_lines
        previous_active_command_guard_names = (
            self.active_command_guard_names
        )
        previous_post_command_guards = self.post_command_guard_source_lines
        previous_active_weak_prefix_guards = (
            self.active_weak_prefix_command_guards
        )
        if previous_function is not None:
            self.enclosing_function_scopes.append(previous_function)
        self.current_function = node
        self.env, self.lists, self.maps = {}, {}, {}
        self.active_command_guard_source_lines = []
        self.active_command_guard_names = []
        self.post_command_guard_source_lines = set()
        self.active_weak_prefix_command_guards = []
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if _looks_like_request_name(arg.arg) or (node.name.startswith("resolve_") and arg.arg not in {"self", "root", "info"}):
                self.env[arg.arg] = self._tainted(node.lineno)
        self._analyze_block(node.body)
        self._restore(previous)
        self.active_command_guard_source_lines = (
            previous_active_command_guards
        )
        self.active_command_guard_names = (
            previous_active_command_guard_names
        )
        self.post_command_guard_source_lines = previous_post_command_guards
        self.active_weak_prefix_command_guards = (
            previous_active_weak_prefix_guards
        )
        self.current_function = previous_function
        if previous_function is not None:
            self.enclosing_function_scopes.pop()

    def _analyze_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self._analyze_statement(statement)

    def _analyze_statement(self, node: ast.stmt) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._analyze_function(node)
            return
        if isinstance(node, ast.Assign):
            self._check_calls(node.value)
            value = self._eval(node.value)
            for target in node.targets:
                self._assign(target, value, node.value)
            return
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._check_calls(node.value)
                self._assign(node.target, self._eval(node.value), node.value)
            return
        if isinstance(node, ast.AugAssign):
            self._check_calls(node.value)
            current = self._eval(node.target)
            value = self._merge(current, self._eval(node.value))
            self._assign(node.target, value, node.value)
            return
        if isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call):
                self._check_sink(node.value)
                self._apply_container_call(node.value)
            else:
                self._check_calls(node.value)
            return
        if isinstance(node, ast.Return):
            if node.value is not None:
                self._check_calls(node.value)
                value = self._eval(node.value)
                if (
                    value.tainted
                    and "html" not in value.sanitized_for
                    and self._looks_like_html_response(node.value)
                ):
                    self._append_finding("WEB_UNTRUSTED_INPUT_TO_HTML", "html_response", value, node.lineno)
            return
        if isinstance(node, ast.If):
            self._analyze_branch(node.test, node.body, node.orelse)
            self._apply_post_guard(node.test, node.body, node.orelse)
            return
        if isinstance(node, ast.Match):
            self._analyze_match(node)
            return
        if isinstance(node, ast.Try):
            self._analyze_try(node)
            return
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            base = self._snapshot()
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self._check_calls(node.iter)
                self._assign(node.target, self._eval(node.iter), node.iter)
            self._analyze_block(node.body)
            body_state = self._snapshot()
            self._restore(base)
            self._analyze_block(node.orelse)
            self._restore(self._merge_states(body_state, self._snapshot()))
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._check_calls(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, self._eval(item.context_expr), item.context_expr)
            self._analyze_block(node.body)
            return

    def _analyze_branch(self, test: ast.AST, body: list[ast.stmt], orelse: list[ast.stmt]) -> None:
        self._check_calls(test)
        truth = self._constant_truth(test)
        command_guard_lines = self._constraining_command_guard_source_lines(
            test
        )
        command_guard_names = self._constraining_command_guard_names(test)
        weak_prefix_guards = self._weak_prefix_command_guard_bindings(test)
        if truth is True:
            self._analyze_command_guarded_block(
                body,
                command_guard_lines,
                weak_prefix_guards,
                command_guard_names,
            )
            return
        if truth is False:
            self._analyze_command_guarded_block(
                orelse,
                command_guard_lines,
                command_guard_names=command_guard_names,
            )
            return
        base = self._snapshot()
        self._analyze_command_guarded_block(
            body,
            command_guard_lines,
            weak_prefix_guards,
            command_guard_names,
        )
        body_state = self._snapshot()
        self._restore(base)
        self._analyze_command_guarded_block(
            orelse,
            command_guard_lines,
            command_guard_names=command_guard_names,
        )
        else_state = self._snapshot()
        self._restore(self._merge_states(body_state, else_state))
        if command_guard_lines and (
            self._block_always_exits(body)
            or self._block_always_exits(orelse)
        ):
            self.post_command_guard_source_lines.update(
                command_guard_lines
            )

    def _analyze_command_guarded_block(
        self,
        statements: list[ast.stmt],
        source_lines: frozenset[int],
        weak_prefix_guards: frozenset[tuple[int, str]] = frozenset(),
        command_guard_names: frozenset[str] = frozenset(),
    ) -> None:
        if (
            not source_lines
            and not weak_prefix_guards
            and not command_guard_names
        ):
            self._analyze_block(statements)
            return
        self.active_command_guard_source_lines.append(source_lines)
        self.active_command_guard_names.append(command_guard_names)
        if weak_prefix_guards:
            self.active_weak_prefix_command_guards.append(
                weak_prefix_guards
            )
        try:
            self._analyze_block(statements)
        finally:
            if weak_prefix_guards:
                self.active_weak_prefix_command_guards.pop()
            self.active_command_guard_names.pop()
            self.active_command_guard_source_lines.pop()

    def _constraining_command_guard_source_lines(
        self,
        test: ast.AST,
    ) -> frozenset[int]:
        if _python_is_bare_truthiness_guard(test):
            return frozenset()
        value = self._eval(test)
        if not value.tainted:
            return frozenset()
        lines = {
            self.env[name.id].source_line
            for name in ast.walk(test)
            if isinstance(name, ast.Name)
            and name.id in self.env
            and self.env[name.id].tainted
            and self.env[name.id].source_line is not None
        }
        if value.source_line is not None:
            lines.add(value.source_line)
        return frozenset(lines)

    def _constraining_command_guard_names(
        self,
        test: ast.AST,
    ) -> frozenset[str]:
        if _python_is_bare_truthiness_guard(test):
            return frozenset()
        value = self._eval(test)
        if not value.tainted:
            return frozenset()
        return frozenset(
            name.id
            for name in ast.walk(test)
            if isinstance(name, ast.Name)
            and name.id in self.env
            and self.env[name.id].tainted
        )

    def _weak_prefix_command_guard_bindings(
        self,
        test: ast.AST,
    ) -> frozenset[tuple[int, str]]:
        if not isinstance(test, ast.Call):
            return frozenset()
        call_name = _call_name(test.func).lower()
        parts = call_name.split(".")
        summary_name: str | None = None
        module_name: str | None = None
        if len(parts) == 1 and parts[0] in self.imported_functions:
            module_name, summary_name = self.imported_functions[parts[0]]
        elif len(parts) > 1 and parts[0] in self.imported_modules:
            summary_name = parts[-1]
            imported_root = self.imported_modules[parts[0]]
            suffix = ".".join(parts[1:-1])
            module_name = ".".join(
                part
                for part in (imported_root, suffix)
                if part
            )
        if not summary_name or not module_name:
            return frozenset()
        summaries = [
            summary
            for summary in self.weak_prefix_guard_summaries.get(
                summary_name,
                [],
            )
            if _python_source_file_matches_module(
                summary.file,
                module_name,
            )
        ]
        if len(summaries) != 1:
            return frozenset()
        summary = summaries[0]
        if (
            summary.guarded_param_index != 0
            or len(summary.param_names) != 1
            or len(test.args) != 1
            or test.keywords
            or not isinstance(test.args[0], ast.Name)
            or not self._consumer_call_binding_is_stable(
                call_name,
                source_file=summary.file,
                allow_verified_star_imports=True,
            )
        ):
            return frozenset()
        value = self._eval(test.args[0])
        if (
            not value.tainted
            or value.constant_known
            or value.source_line is None
        ):
            return frozenset()
        return frozenset(
            {
                (
                    value.source_line,
                    test.args[0].id,
                )
            }
        )

    def _analyze_match(self, node: ast.Match) -> None:
        subject = self._eval(node.subject)
        if subject.constant_known:
            for case in node.cases:
                if self._pattern_matches(case.pattern, subject.constant):
                    self._analyze_block(case.body)
                    return
            return
        base = self._snapshot()
        states = []
        for case in node.cases:
            self._restore(base)
            self._analyze_block(case.body)
            states.append(self._snapshot())
        if states:
            merged = states[0]
            for state in states[1:]:
                merged = self._merge_states(merged, state)
            self._restore(merged)

    def _analyze_try(self, node: ast.Try) -> None:
        base = self._snapshot()
        states = []
        self._analyze_block(node.body)
        self._analyze_block(node.orelse)
        if not self._block_always_exits([*node.body, *node.orelse]):
            states.append(self._snapshot())
        for handler in node.handlers:
            self._restore(base)
            self._analyze_block(handler.body)
            if not self._block_always_exits(handler.body):
                states.append(self._snapshot())
        if not states:
            self._restore(base)
            self._analyze_block(node.finalbody)
            return
        merged = states[0]
        for state in states[1:]:
            merged = self._merge_states(merged, state)
        self._restore(merged)
        self._analyze_block(node.finalbody)

    def _assign(self, target: ast.AST, value: PythonSecurityValue, expression: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value
            if isinstance(expression, (ast.List, ast.Tuple)):
                self.lists[target.id] = [self._eval(item) for item in expression.elts]
                self.maps.pop(target.id, None)
            elif isinstance(expression, ast.Dict):
                mapping: dict[object, PythonSecurityValue] = {}
                for key, item in zip(expression.keys, expression.values):
                    key_value = self._eval(key) if key is not None else self._unknown()
                    if key_value.constant_known:
                        mapping[key_value.constant] = self._eval(item)
                self.maps[target.id] = mapping
                self.lists.pop(target.id, None)
            else:
                self.lists.pop(target.id, None)
                self.maps.pop(target.id, None)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, value, expression)
            return
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            name = target.value.id
            key = self._eval(target.slice)
            if key.constant_known:
                if name in self.lists and isinstance(key.constant, int):
                    values = self.lists[name]
                    index = int(key.constant)
                    if -len(values) <= index < len(values):
                        values[index] = value
                    elif index == len(values):
                        values.append(value)
                    self.env[name] = self._merge_many(values)
                else:
                    self.maps.setdefault(name, {})[key.constant] = value
                    self.env[name] = self._merge_many(list(self.maps[name].values()))

    def _eval(self, node: ast.AST | None) -> PythonSecurityValue:
        if node is None:
            return self._clean(None, known=True)
        if isinstance(node, ast.Constant):
            return self._clean(node.value, known=True)
        if isinstance(node, ast.Name):
            if node.id.lower() in {"request", "req"}:
                return self._tainted(getattr(node, "lineno", 1))
            return self.env.get(node.id, self._unknown())
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id.lower() in {"request", "req"} and node.attr.lower() == "path":
                return self._clean()
            return self._eval(node.value)
        if isinstance(node, ast.NamedExpr):
            value = self._eval(node.value)
            self._assign(node.target, value, node.value)
            return value
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.JoinedStr):
            return self._merge_many([self._eval(value) for value in node.values])
        if isinstance(node, ast.FormattedValue):
            value = self._eval(node.value)
            if node.conversion == -1 and node.format_spec is None:
                return value
            return _python_security_without_sanitizer_domain(value, "html")
        if isinstance(node, ast.BinOp):
            left = self._eval(node.left)
            right = self._eval(node.right)
            constant, known = self._binary_constant(left, right, node.op)
            merged = self._merge(left, right)
            return PythonSecurityValue(merged.tainted, merged.source_line, constant, known, merged.sanitized_for)
        if isinstance(node, ast.UnaryOp):
            value = self._eval(node.operand)
            if value.constant_known:
                try:
                    if isinstance(node.op, ast.Not):
                        return PythonSecurityValue(value.tainted, value.source_line, not value.constant, True, value.sanitized_for)
                    if isinstance(node.op, ast.USub):
                        return PythonSecurityValue(value.tainted, value.source_line, -value.constant, True, value.sanitized_for)
                except Exception:
                    pass
            return PythonSecurityValue(value.tainted, value.source_line)
        if isinstance(node, ast.BoolOp):
            values = [self._eval(item) for item in node.values]
            merged = self._merge_many(values)
            if all(item.constant_known for item in values):
                constants = [item.constant for item in values]
                constant = all(constants) if isinstance(node.op, ast.And) else any(constants)
                return PythonSecurityValue(merged.tainted, merged.source_line, constant, True, merged.sanitized_for)
            return merged
        if isinstance(node, ast.Compare):
            return self._eval_compare(node)
        if isinstance(node, ast.IfExp):
            truth = self._constant_truth(node.test)
            if truth is True:
                return self._eval(node.body)
            if truth is False:
                return self._eval(node.orelse)
            return self._merge(self._eval(node.body), self._eval(node.orelse))
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._merge_many([self._eval(item) for item in node.elts])
        if isinstance(node, ast.Dict):
            return self._merge_many([self._eval(item) for item in node.values])
        values = [self._eval(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return self._merge_many(values)

    def _eval_call(self, node: ast.Call) -> PythonSecurityValue:
        name = _call_name(node.func).lower()
        if self._is_source_call(name):
            return self._tainted(node.lineno)
        if self._standard_html_sanitizer_matches_call(
            name,
            node,
        ) or self._custom_html_sanitizer_matches_call(name, node):
            merged = self._merge_many(
                [
                    *[self._eval(arg) for arg in node.args],
                    *[self._eval(keyword.value) for keyword in node.keywords],
                ]
            )
            return PythonSecurityValue(
                merged.tainted,
                merged.source_line,
                merged.constant,
                merged.constant_known,
                merged.sanitized_for.union({"html"}),
            )
        summary_name = name.rsplit(".", 1)[-1]
        summary = self.function_summaries.get(summary_name)
        same_file_request_backfill = (
            summary is not None
            and summary_name in self.same_file_request_backfills
            and summary.return_kind == "request"
            and "." not in name
            and Path(summary.source_file).resolve() == self.path.resolve()
        )
        if summary is not None and (
            (
                summary.return_kind != "html_sanitized"
                and not same_file_request_backfill
            )
            or self._function_summary_matches_call(summary, name, node)
        ):
            if summary.return_kind == "constant":
                return self._clean(summary.constant, known=True)
            if summary.return_kind == "request":
                return self._tainted(node.lineno)
            if (
                summary.return_kind == "html_sanitized"
                and summary.html_sanitizer_dependencies.issubset(
                    self.available_html_sanitizer_dependencies
                )
            ):
                merged = self._merge_many(
                    [
                        *[self._eval(arg) for arg in node.args],
                        *[self._eval(keyword.value) for keyword in node.keywords],
                    ]
                )
                return PythonSecurityValue(
                    merged.tainted,
                    merged.source_line,
                    sanitized_for=merged.sanitized_for.union({"html"}),
                )
        if name.endswith("make_response") and node.args:
            payload = node.args[0]
            if isinstance(payload, (ast.Tuple, ast.List)) and payload.elts:
                payload = payload.elts[0]
            return self._eval(payload)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            base = node.func.value.id
            if node.func.attr == "pop" and base in self.lists:
                index_value = self._eval(node.args[0]) if node.args else self._clean(-1, known=True)
                index = int(index_value.constant) if index_value.constant_known and isinstance(index_value.constant, int) else -1
                values = self.lists[base]
                if values and -len(values) <= index < len(values):
                    value = values.pop(index)
                    self.env[base] = self._merge_many(values)
                    return value
            if node.func.attr == "get" and base in self.maps and node.args:
                key_values = [self._eval(arg) for arg in node.args[:2]]
                if len(key_values) >= 2 and all(value.constant_known for value in key_values):
                    compound = (key_values[0].constant, key_values[1].constant)
                    if compound in self.maps[base]:
                        return self.maps[base][compound]
                key = key_values[0]
                if key.constant_known:
                    return self.maps[base].get(key.constant, self._eval(node.args[1]) if len(node.args) > 1 else self._unknown())
        argument_values = [self._eval(arg) for arg in node.args]
        argument_values.extend(
            self._eval(keyword.value)
            for keyword in node.keywords
        )
        values = list(argument_values)
        receiver: PythonSecurityValue | None = None
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval(node.func.value)
            values.append(receiver)
        merged = self._merge_many(values)
        if (
            receiver is not None
            and node.func.attr == "replace"
            and "html" in merged.sanitized_for
        ):
            replacement = (
                argument_values[1]
                if len(argument_values) >= 2
                else self._unknown()
            )
            if not _python_html_replacement_preserves_safety(
                replacement.constant,
                replacement.constant_known,
            ):
                return _python_security_without_sanitizer_domain(
                    merged,
                    "html",
                )
            return merged
        constant = self._known_builtin_constant(name, values)
        result = merged
        if constant is not None:
            result = PythonSecurityValue(
                merged.tainted,
                merged.source_line,
                constant,
                True,
                merged.sanitized_for,
            )
        if (
            "html" in result.sanitized_for
            and not self._runtime_call_preserves_html(
                node,
                name,
                argument_values,
                receiver,
            )
        ):
            return _python_security_without_sanitizer_domain(
                result,
                "html",
            )
        return result

    def _runtime_call_preserves_html(
        self,
        node: ast.Call,
        name: str,
        argument_values: list[PythonSecurityValue],
        receiver: PythonSecurityValue | None,
    ) -> bool:
        if name == "str":
            return True
        if not isinstance(node.func, ast.Attribute):
            return False
        method = node.func.attr.lower()
        if method == "format":
            return (
                receiver is not None
                and _python_constant_format_preserves_html(
                    receiver.constant,
                    receiver.constant_known,
                )
            )
        if method in {
            "capitalize",
            "casefold",
            "lower",
            "lstrip",
            "removeprefix",
            "removesuffix",
            "rstrip",
            "strip",
            "swapcase",
            "title",
            "upper",
        }:
            return True
        if method not in {"encode", "decode"}:
            return False
        if not argument_values:
            return True
        codec = argument_values[0]
        return (
            codec.constant_known
            and isinstance(codec.constant, str)
            and codec.constant.replace("_", "-").lower()
            in {"ascii", "utf-8", "utf8"}
        )

    def _eval_subscript(self, node: ast.Subscript) -> PythonSecurityValue:
        key = self._eval(node.slice)
        if isinstance(node.value, ast.Name) and key.constant_known:
            name = node.value.id
            if name in self.lists and isinstance(key.constant, int):
                values = self.lists[name]
                index = int(key.constant)
                if -len(values) <= index < len(values):
                    return values[index]
            if name in self.maps:
                return self.maps[name].get(key.constant, self._unknown())
        container = self._eval(node.value)
        if container.constant_known and key.constant_known:
            try:
                return PythonSecurityValue(container.tainted, container.source_line, container.constant[key.constant], True)
            except Exception:
                pass
        return PythonSecurityValue(container.tainted, container.source_line, sanitized_for=container.sanitized_for)

    def _apply_container_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
            return
        base = node.func.value.id
        if node.func.attr == "append" and node.args:
            value = self._eval(node.args[0])
            self.lists.setdefault(base, []).append(value)
            self.env[base] = self._merge_many(self.lists[base])
        elif node.func.attr == "pop" and base in self.lists:
            self._eval_call(node)
        elif node.func.attr == "set" and len(node.args) >= 3:
            section = self._eval(node.args[0])
            key = self._eval(node.args[1])
            value = self._eval(node.args[2])
            if section.constant_known and key.constant_known:
                self.maps.setdefault(base, {})[(section.constant, key.constant)] = value
                self.env[base] = self._merge_many(list(self.maps[base].values()))

    def _check_calls(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._check_sink(child)

    def _check_sink(self, node: ast.Call) -> None:
        name = _call_name(node.func).lower()
        args = [self._eval(arg) for arg in node.args]
        self._check_cross_file_sink(node, name)
        if name.endswith((".execute", ".executemany", ".query", ".raw")) and args and args[0].tainted:
            self._append_finding("WEB_UNTRUSTED_INPUT_TO_SQL", "python_ast_sql", args[0], node.lineno)
        if name in {"os.system", "os.popen", "eval", "exec"} or name.endswith(("subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_output")):
            command = self._merge_many(args)
            if command.tainted:
                subtype = (
                    "python_ast_proven_unguarded_command"
                    if self._direct_command_proof_succeeds(
                        node,
                        name,
                        command,
                    )
                    else "python_ast_command"
                )
                self._append_finding(
                    "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                    subtype,
                    command,
                    node.lineno,
                )
        path_names = ("open", "codecs.open", "io.open", "pathlib.path", "path", "send_file", "send_from_directory")
        path_method_suffixes = (
            ".open",
            ".read_text",
            ".write_text",
            ".read_bytes",
            ".write_bytes",
            ".exists",
            ".is_file",
            ".is_dir",
            ".stat",
            ".glob",
            ".rglob",
        )
        if name in path_names or name == "os.path.exists" or name.endswith(path_method_suffixes):
            path_values = list(args if name == "send_from_directory" else args[:1])
            if isinstance(node.func, ast.Attribute):
                path_values.append(self._eval(node.func.value))
            path_value = self._merge_many(path_values)
            if path_value.tainted and "path" not in path_value.sanitized_for:
                self._append_finding("WEB_UNTRUSTED_INPUT_TO_FILE_PATH", "python_ast_file_path", path_value, node.lineno)
        if name.endswith("redirect"):
            keyword_destinations = [
                keyword.value
                for keyword in node.keywords
                if keyword.arg
                and keyword.arg.lower() in {"location", "redirect_uri", "target", "to", "url"}
            ]
            if keyword_destinations:
                destination_nodes = keyword_destinations
            elif len(node.args) >= 2 and _python_is_request_context(node.args[0]):
                destination_nodes = list(node.args[1:2])
            else:
                destination_nodes = list(node.args[:1])
            destination = self._merge_many([self._eval(value) for value in destination_nodes])
            if destination.tainted and "redirect" not in destination.sanitized_for:
                self._append_finding("API_OPEN_REDIRECT_REQUEST_INPUT", "python_ast_redirect", destination, node.lineno)
        if name.startswith(("requests.", "httpx.", "urllib.request.")) and args and args[0].tainted:
            self._append_finding("WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST", "python_ast_outbound_url", args[0], node.lineno)
        if name.endswith(("make_response", "render_template_string")) and node.args:
            payload = node.args[0]
            if isinstance(payload, (ast.Tuple, ast.List)) and payload.elts:
                payload = payload.elts[0]
            html_value = self._eval(payload)
            if html_value.tainted and "html" not in html_value.sanitized_for:
                self._append_finding("WEB_UNTRUSTED_INPUT_TO_HTML", "python_ast_html_response", html_value, node.lineno)
        if name.endswith(("set_cookie", ".cookie")):
            for keyword in node.keywords:
                if keyword.arg and keyword.arg.lower() in {"secure", "httponly", "http_only"}:
                    value = self._eval(keyword.value)
                    if value.constant_known and value.constant is False:
                        self._append_finding("AUTH_COOKIE_SECURITY_FLAG_DISABLED", "python_ast_cookie_flag", self._clean(), node.lineno)
                        break

    def _collect_import_bindings(self, tree: ast.AST) -> None:
        function_bindings: dict[str, set[tuple[str, str]]] = {}
        module_bindings: dict[str, set[str]] = {}
        for node in _python_unconditional_import_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                module = _python_import_module(self.path, node.module, node.level)
                for alias in node.names:
                    local_name = (alias.asname or alias.name).lower()
                    function_bindings.setdefault(local_name, set()).add(
                        (module, alias.name)
                    )
                    imported_module = ".".join(part for part in (module, alias.name) if part)
                    module_bindings.setdefault(local_name, set()).add(
                        imported_module
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        module_bindings.setdefault(
                            alias.asname.lower(),
                            set(),
                        ).add(alias.name)
                    else:
                        root = alias.name.split(".", 1)[0]
                        module_bindings.setdefault(root.lower(), set()).add(
                            root
                        )
        self.imported_functions = {
            name: next(iter(bindings))
            for name, bindings in function_bindings.items()
            if len(bindings) == 1
        }
        self.imported_modules = {
            name: next(iter(bindings))
            for name, bindings in module_bindings.items()
            if len(bindings) == 1
        }

    def _function_summary_matches_call(
        self,
        summary: PythonFunctionSummary,
        call_name: str,
        node: ast.Call,
    ) -> bool:
        summary_name = call_name.rsplit(".", 1)[-1]
        same_file_request_backfill = (
            summary_name in self.same_file_request_backfills
            and summary.return_kind == "request"
            and "." not in call_name
            and Path(summary.source_file).resolve() == self.path.resolve()
        )
        if same_file_request_backfill and any(
            isinstance(scope, ast.AsyncFunctionDef)
            for scope in (
                self.current_function,
                *self.enclosing_function_scopes,
            )
        ):
            return False
        if not self._consumer_call_binding_is_stable(
            call_name,
            source_file=summary.source_file,
            allow_active_local_prefix=same_file_request_backfill,
        ):
            return False
        parts = call_name.split(".")
        if len(parts) == 1:
            imported = self.imported_functions.get(parts[0])
            if imported is not None:
                module_name, imported_name = imported
                return (
                    imported_name.lower() == summary.name
                    and _python_source_file_matches_module(
                        summary.source_file,
                        module_name,
                    )
                )
            return Path(summary.source_file).resolve() == self.path.resolve()
        if parts[0] not in self.imported_modules:
            return False
        imported_root = self.imported_modules[parts[0]]
        suffix = ".".join(parts[1:-1])
        module_name = ".".join(
            part for part in (imported_root, suffix) if part
        )
        return _python_source_file_matches_module(
            summary.source_file,
            module_name,
        )

    def _custom_html_sanitizer_matches_call(
        self,
        call_name: str,
        node: ast.Call,
    ) -> bool:
        sanitizer_name = call_name.rsplit(".", 1)[-1]
        source_file = self.html_sanitizer_files.get(sanitizer_name)
        if source_file is None or not self._consumer_call_binding_is_stable(
            call_name,
            source_file=source_file,
        ):
            return False
        parts = call_name.split(".")
        if len(parts) == 1:
            imported = self.imported_functions.get(parts[0])
            if imported is not None:
                module_name, imported_name = imported
                return (
                    imported_name.lower() == sanitizer_name
                    and _python_source_file_matches_module(
                        source_file,
                        module_name,
                    )
                )
            return Path(source_file).resolve() == self.path.resolve()
        if parts[0] not in self.imported_modules:
            return False
        imported_root = self.imported_modules[parts[0]]
        suffix = ".".join(parts[1:-1])
        module_name = ".".join(
            part for part in (imported_root, suffix) if part
        )
        return _python_source_file_matches_module(source_file, module_name)

    def _standard_html_sanitizer_matches_call(
        self,
        call_name: str,
        node: ast.Call,
    ) -> bool:
        if call_name not in _PYTHON_STANDARD_HTML_SANITIZERS:
            return False
        parts = call_name.split(".")
        if len(parts) != 2:
            return False
        if parts[0] in self.local_python_modules:
            return False
        imported_module = self.imported_modules.get(parts[0])
        return (
            imported_module == parts[0]
            and self._consumer_call_binding_is_stable(call_name)
        )

    def _consumer_call_binding_is_stable(
        self,
        call_name: str,
        *,
        source_file: str | None = None,
        allow_active_local_prefix: bool = False,
        allow_verified_star_imports: bool = False,
    ) -> bool:
        if self.tree is None or self.current_function is None:
            return False
        root_name = call_name.split(".", 1)[0].casefold()
        if (
            allow_verified_star_imports
            and not self._star_imports_exclude_call_root(root_name)
        ):
            return False
        parameters = [
            *self.current_function.args.posonlyargs,
            *self.current_function.args.args,
            *self.current_function.args.kwonlyargs,
        ]
        if self.current_function.args.vararg is not None:
            parameters.append(self.current_function.args.vararg)
        if self.current_function.args.kwarg is not None:
            parameters.append(self.current_function.args.kwarg)
        if any(
            parameter.arg.casefold() == root_name
            for parameter in parameters
        ):
            return False
        for function_scope in self.enclosing_function_scopes:
            parameters = [
                *function_scope.args.posonlyargs,
                *function_scope.args.args,
                *function_scope.args.kwonlyargs,
            ]
            if function_scope.args.vararg is not None:
                parameters.append(function_scope.args.vararg)
            if function_scope.args.kwarg is not None:
                parameters.append(function_scope.args.kwarg)
            if any(
                parameter.arg.casefold() == root_name
                for parameter in parameters
            ):
                return False
        if _python_definition_header_requires_binding_review(
            self.current_function
        ):
            if not self.function_parent_scopes_ready:
                self.function_parent_scopes = (
                    _python_function_parent_scopes(self.tree)
                )
                self.function_parent_scopes_ready = True
            parent_scope = self.function_parent_scopes.get(
                self.current_function
            )
            if (
                parent_scope is not None
                and self._definition_header_may_replace_call_binding(
                    self.current_function,
                    parent_scope,
                    call_name,
                )
            ):
                return False
        for function_scope in self.enclosing_function_scopes:
            if not _python_definition_header_requires_binding_review(
                function_scope
            ):
                continue
            if not self.function_parent_scopes_ready:
                self.function_parent_scopes = (
                    _python_function_parent_scopes(self.tree)
                )
                self.function_parent_scopes_ready = True
            parent_scope = self.function_parent_scopes.get(function_scope)
            if (
                parent_scope is not None
                and self._definition_header_may_replace_call_binding(
                    function_scope,
                    parent_scope,
                    call_name,
                )
            ):
                return False
        allowed_definition = None
        if (
            source_file is not None
            and "." not in call_name
            and Path(source_file).resolve() == self.path.resolve()
        ):
            allowed_definition = root_name
        if self._scope_may_replace_call_binding(
            self.tree,
            call_name,
            allowed_definition=allowed_definition,
            allow_active_local_prefix=allow_active_local_prefix,
            ignore_star_imports=allow_verified_star_imports,
        ) or self._scope_may_replace_call_binding(
            self.current_function,
            call_name,
            ignore_star_imports=allow_verified_star_imports,
        ):
            return False
        return not any(
            self._scope_may_replace_call_binding(
                function_scope,
                call_name,
                ignore_star_imports=allow_verified_star_imports,
            )
            for function_scope in self.enclosing_function_scopes
        )

    def _star_imports_exclude_call_root(
        self,
        root_name: str,
    ) -> bool:
        if self.tree is None or self.current_function is None:
            return False
        scopes: list[ast.AST] = [
            self.tree,
            self.current_function,
            *self.enclosing_function_scopes,
        ]
        imports = [
            node
            for scope in scopes
            for node in _python_nodes_in_lexical_scope(scope)
            if isinstance(node, ast.ImportFrom)
            and any(alias.name == "*" for alias in node.names)
        ]
        return all(
            _python_star_import_excludes_name(
                self.path,
                node,
                root_name,
            )
            for node in imports
        )

    def _scope_may_replace_call_binding(
        self,
        scope: ast.AST,
        call_name: str,
        *,
        allowed_definition: str | None = None,
        allow_active_local_prefix: bool = False,
        ignore_star_imports: bool = False,
    ) -> bool:
        key = (
            id(scope),
            call_name,
            allowed_definition,
            allow_active_local_prefix,
            ignore_star_imports,
        )
        if key not in self.call_binding_cache:
            self.call_binding_cache[key] = (
                _python_scope_may_replace_call_binding(
                    scope,
                    call_name,
                    allowed_definition=allowed_definition,
                    allow_active_local_prefix=allow_active_local_prefix,
                    ignore_star_imports=ignore_star_imports,
                    binding_resolution_nodes=(
                        []
                        if scope is self.tree
                        else self.module_binding_resolution_nodes
                    ),
                )
            )
        return self.call_binding_cache[key]

    def _definition_header_may_replace_call_binding(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent_scope: ast.AST,
        call_name: str,
    ) -> bool:
        key = (id(node), call_name)
        if key not in self.definition_header_binding_cache:
            self.definition_header_binding_cache[key] = (
                _python_definition_header_may_replace_call_binding(
                    node,
                    parent_scope,
                    call_name,
                )
            )
        return self.definition_header_binding_cache[key]

    def _direct_command_proof_succeeds(
        self,
        node: ast.Call,
        call_name: str,
        source: PythonSecurityValue,
    ) -> bool:
        return (
            _python_shell_command_primitive(node) == call_name
            and call_name in {"os.system", "os.popen"}
            and not source.constant_known
            and call_name.split(".", 1)[0]
            not in self.local_python_modules
            and self.imported_modules.get(
                call_name.split(".", 1)[0]
            )
            == call_name.split(".", 1)[0]
            and self._consumer_call_binding_is_stable(call_name)
            and self._command_source_is_unguarded(source)
        )

    def _command_source_is_unguarded(
        self,
        source: PythonSecurityValue,
    ) -> bool:
        if source.source_line is None:
            return False
        if (
            any(self.active_command_guard_names)
            or any(self.active_command_guard_source_lines)
            or self.post_command_guard_source_lines
        ):
            return False
        guarded_lines = set(self.post_command_guard_source_lines)
        for active in self.active_command_guard_source_lines:
            guarded_lines.update(active)
        return source.source_line not in guarded_lines

    def _weak_prefix_command_proof_succeeds(
        self,
        node: ast.Call,
        summary: PythonSinkSummary,
        source: PythonSecurityValue,
    ) -> bool:
        if (
            source.source_line is None
            or source.source_line in self.post_command_guard_source_lines
            or summary.dangerous_param_indexes != (0,)
            or len(summary.param_names) != 1
            or len(node.args) != 1
            or node.keywords
            or not isinstance(node.args[0], ast.Name)
            or self._command_name_was_reassigned_after_source(
                node.args[0].id,
                source.source_line,
                node.lineno,
            )
        ):
            return False
        active_guard_count = sum(
            node.args[0].id in guard_names
            for guard_names in self.active_command_guard_names
        )
        weak_guard_count = sum(
            (
                source.source_line,
                node.args[0].id,
            )
            in guard_bindings
            for guard_bindings in self.active_weak_prefix_command_guards
        )
        return active_guard_count == weak_guard_count == 1

    def _command_name_was_reassigned_after_source(
        self,
        name: str,
        source_line: int,
        sink_line: int,
    ) -> bool:
        if self.current_function is None:
            return True
        for candidate in ast.walk(self.current_function):
            if not isinstance(
                candidate,
                (ast.Assign, ast.AnnAssign, ast.AugAssign),
            ):
                continue
            line = int(getattr(candidate, "lineno", 0) or 0)
            if line <= source_line or line >= sink_line:
                continue
            targets = (
                list(candidate.targets)
                if isinstance(candidate, ast.Assign)
                else [candidate.target]
            )
            if any(
                name in _target_names(target)
                for target in targets
            ):
                return True
        return False

    def _check_cross_file_sink(self, node: ast.Call, call_name: str) -> None:
        parts = call_name.split(".")
        summary_name: str | None = None
        module_name: str | None = None
        if len(parts) == 1 and parts[0] in self.imported_functions:
            module_name, summary_name = self.imported_functions[parts[0]]
        elif len(parts) > 1 and parts[0] in self.imported_modules:
            summary_name = parts[-1]
            imported_root = self.imported_modules[parts[0]]
            suffix = ".".join(parts[1:-1])
            module_name = ".".join(part for part in (imported_root, suffix) if part)
        if not summary_name or not module_name:
            return
        summaries = [
            summary
            for summary in self.sink_summaries.get(summary_name, [])
            if _python_summary_matches_module(summary, module_name)
        ]
        if len(summaries) != 1:
            return
        summary = summaries[0]
        values: list[PythonSecurityValue] = []
        for index in summary.dangerous_param_indexes:
            if index < len(node.args):
                values.append(self._eval(node.args[index]))
                continue
            if index < len(summary.param_names):
                parameter = summary.param_names[index]
                values.extend(self._eval(keyword.value) for keyword in node.keywords if keyword.arg == parameter)
        source = self._merge_many(values)
        if source.tainted:
            command_proof_base = (
                summary.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
                and summary.proven_command_primitive
                in {"os.system", "os.popen"}
                and not source.constant_known
                and self._consumer_call_binding_is_stable(
                    call_name,
                    source_file=summary.file,
                    allow_verified_star_imports=True,
                )
            )
            proof_qualified = (
                command_proof_base
                and self._command_source_is_unguarded(source)
            )
            weak_prefix_proof_qualified = (
                command_proof_base
                and self._weak_prefix_command_proof_succeeds(
                    node,
                    summary,
                    source,
                )
            )
            self._append_cross_file_finding(
                summary,
                source,
                node.lineno,
                proof_qualified=proof_qualified,
                weak_prefix_proof_qualified=(
                    weak_prefix_proof_qualified
                ),
            )

    def _append_cross_file_finding(
        self,
        summary: PythonSinkSummary,
        source: PythonSecurityValue,
        call_line: int,
        *,
        proof_qualified: bool = False,
        weak_prefix_proof_qualified: bool = False,
    ) -> None:
        key = (summary.rule_id, call_line)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        severity = "critical" if summary.rule_id in {"WEB_UNTRUSTED_INPUT_TO_SQL", "WEB_UNTRUSTED_INPUT_TO_COMMAND"} else "high"
        title = {
            "WEB_UNTRUSTED_INPUT_TO_SQL": "Request input reaches an imported Python SQL execution helper",
            "WEB_UNTRUSTED_INPUT_TO_COMMAND": "Request input reaches an imported Python command execution helper",
            "WEB_UNTRUSTED_INPUT_TO_FILE_PATH": "Request input reaches an imported Python filesystem helper",
            "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST": "Request input controls an imported Python outbound-request helper",
        }[summary.rule_id]
        source_line = source.source_line or call_line
        source_id = self._node_id("source", "python request input", source_line)
        sink_id = f"PX{len(self.flow.nodes) + 1}"
        self.flow.nodes.append(FlowNode(sink_id, "sink", "python imported helper sink", summary.file, summary.line))
        self.flow.edges.append(FlowEdge(source_id, sink_id, "python bounded cross-file parameter summary"))
        subtype = (
            "python_ast_proven_weak_prefix_guard_cross_file_command"
            if weak_prefix_proof_qualified
            else (
                "python_ast_proven_unguarded_cross_file_command"
                if proof_qualified
                else "python_ast_bounded_cross_file_parameter_flow"
            )
        )
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="python-security-taint",
                rule_id=summary.rule_id,
                severity=severity,
                confidence=(
                    "high"
                    if proof_qualified or weak_prefix_proof_qualified
                    else "medium"
                ),
                title=title,
                file=str(self.path),
                line_start=call_line,
                line_end=call_line,
                evidence=(
                    "detector_subtype="
                    f"{subtype} "
                    f"source_line={source_line} call_line={call_line} helper_line={summary.line} "
                    f"source_hash={_line_hash(self.lines, source_line)} call_hash={_line_hash(self.lines, call_line)} "
                    f"helper_hash={summary.line_hash} helper_file_hash={evidence_hash(summary.file)} raw_returned=false"
                ),
                why_it_matters="A request-controlled value crosses an imported helper boundary and reaches a server-side security sink.",
                recommendation="Validate and constrain the value before the helper call, then use a parameterized or allowlisted sink API inside the helper.",
                audit_depth=5,
                inspected_scope="A project-level Python AST pass summarized direct parameter dependencies in imported helpers and matched a unique import binding at the request call site.",
                not_inspected="This bounded pass does not resolve dynamic imports, decorators, monkey-patching, dependency injection, polymorphism, or helper names that are ambiguous across files.",
            )
        )

    def _append_finding(self, rule_id: str, subtype: str, source: PythonSecurityValue, sink_line: int) -> None:
        key = (rule_id, sink_line)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        severity = "critical" if rule_id in {"WEB_UNTRUSTED_INPUT_TO_SQL", "WEB_UNTRUSTED_INPUT_TO_COMMAND"} else "high"
        title = {
            "WEB_UNTRUSTED_INPUT_TO_SQL": "Request input reaches a Python SQL execution sink",
            "WEB_UNTRUSTED_INPUT_TO_COMMAND": "Request input reaches a Python command execution sink",
            "WEB_UNTRUSTED_INPUT_TO_FILE_PATH": "Request input reaches a Python filesystem path sink",
            "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST": "Request input controls a Python outbound request",
            "API_OPEN_REDIRECT_REQUEST_INPUT": "Request input controls a Python redirect destination",
            "WEB_UNTRUSTED_INPUT_TO_HTML": "Request input reaches an HTML response without a visible sanitizer",
            "AUTH_COOKIE_SECURITY_FLAG_DISABLED": "Python response explicitly disables a cookie security flag",
        }[rule_id]
        source_line = source.source_line or sink_line
        source_id = self._node_id("source", "python request input", source_line)
        sink_id = self._node_id("sink", subtype, sink_line)
        edge_key = (source_id, sink_id, "python security AST taint")
        if not any((edge.source, edge.target, edge.label) == edge_key for edge in self.flow.edges):
            self.flow.edges.append(FlowEdge(source_id, sink_id, "python security AST taint"))
        self.flow.findings.append(
            Finding(
                id=self.ids.next(),
                source="python-security-taint",
                rule_id=rule_id,
                severity=severity,
                confidence=(
                    "high"
                    if (
                        rule_id == "AUTH_COOKIE_SECURITY_FLAG_DISABLED"
                        or subtype
                        == "python_ast_proven_unguarded_command"
                    )
                    else "medium"
                ),
                title=title,
                file=str(self.path),
                line_start=sink_line,
                line_end=sink_line,
                evidence=(
                    f"detector_subtype={subtype} source_line={source_line} sink_line={sink_line} "
                    f"source_hash={_line_hash(self.lines, source_line)} sink_hash={_line_hash(self.lines, sink_line)} raw_returned=false"
                ),
                why_it_matters="Request-controlled data crossing this sink can change server behavior or expose another user's browser, data, files, or session.",
                recommendation="Constrain the input at the authorization boundary and use the sink's structured safe API instead of string or path construction.",
                audit_depth=5,
                inspected_scope="Python AST intra-procedural security taint followed request values through assignments, containers, static branches, and sink calls.",
                not_inspected="This does not resolve arbitrary inter-module calls, runtime framework state, database permissions, or exploitability across every dynamic branch.",
            )
        )

    def _node_id(self, kind: str, label: str, line: int) -> str:
        key = (kind, line, label)
        if key in self.node_ids:
            return self.node_ids[key]
        self.node_counter += 1
        node_id = f"P{len(self.flow.nodes) + self.node_counter}"
        self.node_ids[key] = node_id
        self.flow.nodes.append(FlowNode(node_id, kind, label, str(self.path), line))
        return node_id

    def _constant_truth(self, node: ast.AST) -> bool | None:
        value = self._eval(node)
        return bool(value.constant) if value.constant_known and not value.tainted else None

    def _eval_compare(self, node: ast.Compare) -> PythonSecurityValue:
        values = [self._eval(node.left), *[self._eval(item) for item in node.comparators]]
        merged = self._merge_many(values)
        if not all(item.constant_known for item in values):
            return merged
        try:
            result = True
            left = values[0].constant
            for operator, right_value in zip(node.ops, values[1:]):
                right = right_value.constant
                if isinstance(operator, ast.Eq):
                    comparison = left == right
                elif isinstance(operator, ast.NotEq):
                    comparison = left != right
                elif isinstance(operator, ast.Gt):
                    comparison = left > right
                elif isinstance(operator, ast.GtE):
                    comparison = left >= right
                elif isinstance(operator, ast.Lt):
                    comparison = left < right
                elif isinstance(operator, ast.LtE):
                    comparison = left <= right
                elif isinstance(operator, ast.In):
                    comparison = left in right
                elif isinstance(operator, ast.NotIn):
                    comparison = left not in right
                elif isinstance(operator, ast.Is):
                    comparison = left is right
                elif isinstance(operator, ast.IsNot):
                    comparison = left is not right
                else:
                    return merged
                result = result and comparison
                left = right
            return PythonSecurityValue(merged.tainted, merged.source_line, result, True, merged.sanitized_for)
        except Exception:
            return merged

    def _binary_constant(self, left: PythonSecurityValue, right: PythonSecurityValue, operator: ast.operator) -> tuple[Any, bool]:
        if not left.constant_known or not right.constant_known:
            return None, False
        try:
            if isinstance(operator, ast.Add):
                return left.constant + right.constant, True
            if isinstance(operator, ast.Sub):
                return left.constant - right.constant, True
            if isinstance(operator, ast.Mult):
                return left.constant * right.constant, True
            if isinstance(operator, ast.Div):
                return left.constant / right.constant, True
            if isinstance(operator, ast.FloorDiv):
                return left.constant // right.constant, True
            if isinstance(operator, ast.Mod):
                return left.constant % right.constant, True
            if isinstance(operator, ast.Pow):
                return left.constant**right.constant, True
        except Exception:
            pass
        return None, False

    def _known_builtin_constant(self, name: str, values: list[PythonSecurityValue]) -> Any | None:
        if not values or not all(value.constant_known for value in values):
            return None
        try:
            if name in {"str", "builtins.str"}:
                return str(values[0].constant)
            if name in {"int", "builtins.int"}:
                return int(values[0].constant)
            if name in {"len", "builtins.len"}:
                return len(values[0].constant)
        except Exception:
            return None
        return None

    def _pattern_matches(self, pattern: ast.pattern, value: Any) -> bool:
        if isinstance(pattern, ast.MatchValue):
            expected = self._eval(pattern.value)
            return expected.constant_known and expected.constant == value
        if isinstance(pattern, ast.MatchSingleton):
            return pattern.value is value
        if isinstance(pattern, ast.MatchOr):
            return any(self._pattern_matches(item, value) for item in pattern.patterns)
        if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
            return True
        return False

    def _is_source_call(self, name: str) -> bool:
        if any(name.endswith(method) for method in self._SOURCE_METHODS):
            return True
        return (
            name.startswith(("request.args.", "request.form.", "request.cookies.", "request.headers.", "request.values."))
            or name in {"request.get_json", "input"}
            or name.endswith("request_wrapper")
        )

    def _looks_like_html_response(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id.lower() in {"response", "html", "body", "template", "markup"}
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return True
        if isinstance(node, ast.Call):
            return _call_name(node.func).lower().endswith(("make_response", "render_template_string"))
        return False

    def _apply_post_guard(self, test: ast.AST, body: list[ast.stmt], orelse: list[ast.stmt]) -> None:
        if orelse or not self._block_always_exits(body):
            return
        rendered = _node_text(test).lower()
        domains: set[str] = set()
        if any(marker in rendered for marker in ("../", "..\\", "is_absolute", "startswith(")):
            domains.add("path")
        if ".netloc" in rendered and ".scheme" in rendered:
            domains.add("redirect")
        if not domains:
            return
        named_values = [self.env[name.id] for name in ast.walk(test) if isinstance(name, ast.Name) and name.id in self.env and self.env[name.id].tainted]
        source_lines = {value.source_line for value in named_values if value.source_line}
        for name, value in list(self.env.items()):
            if not value.tainted:
                continue
            if named_values and value not in named_values and value.source_line not in source_lines:
                continue
            self.env[name] = PythonSecurityValue(
                value.tainted,
                value.source_line,
                value.constant,
                value.constant_known,
                value.sanitized_for.union(domains),
            )

    def _block_always_exits(self, statements: list[ast.stmt]) -> bool:
        if not statements:
            return False
        last = statements[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.If):
            return self._block_always_exits(last.body) and self._block_always_exits(last.orelse)
        return False

    def _snapshot(self) -> tuple[dict[str, PythonSecurityValue], dict[str, list[PythonSecurityValue]], dict[str, dict[object, PythonSecurityValue]]]:
        return dict(self.env), {key: list(value) for key, value in self.lists.items()}, {key: dict(value) for key, value in self.maps.items()}

    def _restore(self, state: tuple[dict[str, PythonSecurityValue], dict[str, list[PythonSecurityValue]], dict[str, dict[object, PythonSecurityValue]]]) -> None:
        self.env, self.lists, self.maps = state

    def _merge_states(
        self,
        first: tuple[dict[str, PythonSecurityValue], dict[str, list[PythonSecurityValue]], dict[str, dict[object, PythonSecurityValue]]],
        second: tuple[dict[str, PythonSecurityValue], dict[str, list[PythonSecurityValue]], dict[str, dict[object, PythonSecurityValue]]],
    ) -> tuple[dict[str, PythonSecurityValue], dict[str, list[PythonSecurityValue]], dict[str, dict[object, PythonSecurityValue]]]:
        env = {
            key: self._merge(first[0].get(key, self._unknown()), second[0].get(key, self._unknown()))
            for key in first[0].keys() | second[0].keys()
        }
        lists: dict[str, list[PythonSecurityValue]] = {}
        for key in first[1].keys() | second[1].keys():
            left = first[1].get(key, [])
            right = second[1].get(key, [])
            length = max(len(left), len(right))
            lists[key] = [
                self._merge(left[index] if index < len(left) else self._unknown(), right[index] if index < len(right) else self._unknown())
                for index in range(length)
            ]
        maps: dict[str, dict[object, PythonSecurityValue]] = {}
        for key in first[2].keys() | second[2].keys():
            left = first[2].get(key, {})
            right = second[2].get(key, {})
            maps[key] = {
                item: self._merge(left.get(item, self._unknown()), right.get(item, self._unknown()))
                for item in left.keys() | right.keys()
            }
        return env, lists, maps

    def _merge(self, first: PythonSecurityValue, second: PythonSecurityValue) -> PythonSecurityValue:
        tainted = first.tainted or second.tainted
        source_line = first.source_line if first.tainted else second.source_line
        known = first.constant_known and second.constant_known and first.constant == second.constant
        tainted_values = [value for value in (first, second) if value.tainted]
        sanitized = tainted_values[0].sanitized_for if tainted_values else frozenset()
        for value in tainted_values[1:]:
            sanitized = sanitized.intersection(value.sanitized_for)
        return PythonSecurityValue(tainted, source_line, first.constant if known else None, known, frozenset(sanitized))

    def _merge_many(self, values: list[PythonSecurityValue]) -> PythonSecurityValue:
        if not values:
            return self._clean()
        merged = values[0]
        for value in values[1:]:
            merged = self._merge(merged, value)
        return merged

    def _tainted(self, line: int) -> PythonSecurityValue:
        return PythonSecurityValue(True, line)

    def _clean(self, constant: Any = None, *, known: bool = False) -> PythonSecurityValue:
        return PythonSecurityValue(False, 0, constant, known)

    def _unknown(self) -> PythonSecurityValue:
        return PythonSecurityValue()


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for item in node.elts:
            names.extend(_target_names(item))
        return names
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return []


def _attribute_root_name(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _python_is_request_context(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and _looks_like_request_name(node.id)


def _is_non_sensitive_projection(node: ast.AST) -> bool:
    """Return true when a value is reduced to a non-secret scalar fact."""
    return isinstance(node, ast.Call) and _call_name(node.func).lower() in {"bool", "len"}


def _is_bounded_prefix_slice(node: ast.AST) -> bool:
    if not isinstance(node, ast.Slice) or node.step is not None:
        return False
    lower = node.lower.value if isinstance(node.lower, ast.Constant) else None
    upper = node.upper.value if isinstance(node.upper, ast.Constant) else None
    return (node.lower is None or lower == 0) and isinstance(upper, int) and 0 < upper <= 8


def _source_exposure_rank(source: TaintSource) -> tuple[int, int]:
    return (int(source.sensitive), int(source.projection == "raw"))


def _is_operational_metadata_name(value: str) -> bool:
    normalized = value.lower()
    return normalized in {
        "correlation_id",
        "model_name",
        "model_source",
        "provider",
        "request_id",
        "response_id",
        "session_id",
        "trace_id",
    }


def _field_is_sensitive(value: str) -> bool:
    normalized = value.lower()
    if _is_operational_metadata_name(normalized) or normalized in {"id", "type", "version"}:
        return False
    if normalized in {"body", "content", "message", "prompt", "query", "text"}:
        return True
    return bool(SENSITIVE_NAME.search(normalized))


def _source_kind(node: ast.AST) -> str | None:
    rendered = _node_text(node).lower()
    if any(term in rendered for term in ("request.", "req.", "request[", "get_json", "request_json")):
        return "request_body"
    if any(term in rendered for term in ("os.environ", "getenv", "process.env")):
        return "env"
    if any(term in rendered for term in ("select(", ".query(", ".execute(", ".fetchone(", ".fetchall(")):
        return "db_read"
    if "input(" in rendered:
        return "user_input"
    return None


def _sink_kind(node: ast.Call) -> str | None:
    name = _call_name(node.func).lower()
    if name in {"print", "logging.info", "logging.debug", "logging.warning", "logging.error"} or ".logger." in name or name.startswith("logger."):
        return "log"
    if name.startswith(("requests.", "httpx.", "urllib.request.")):
        return "external_http"
    if any(term in name for term in ("openai", "anthropic", "gemini", "chat.completions", "responses.create", "generate_content")):
        return "llm_call"
    if any(term in name for term in ("call_tool", "use_mcp_tool", "clientsession")):
        return "mcp_tool_call"
    if any(term in name for term in ("jsonify", "response", "jsonresponse")):
        return "response"
    if name.endswith((".execute", ".executemany")):
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            operation = node.args[0].value.lstrip().split(None, 1)[0].lower() if node.args[0].value.strip() else ""
            return "db_write" if operation in {"insert", "update", "delete", "merge", "replace"} else None
        return None
    if any(term in name for term in (".add", ".save", ".insert", ".update")):
        return "db_write"
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def _looks_like_request_name(value: str) -> bool:
    return value.lower() in {"request", "req", "ctx", "event"}


def _request_parameter_is_sensitive(value: str) -> bool:
    return value.lower() in {"request", "req", "ctx"}


def _rule_id_for_sink(sink_kind: str) -> str:
    return {
        "log": "AST_TAINT_PII_TO_LOG",
        "dormant_log": "AST_TAINT_PII_TO_DORMANT_LOG",
        "external_http": "AST_TAINT_PII_TO_EXTERNAL_HTTP",
        "llm_call": "AST_TAINT_PII_TO_AGENTIC_SINK",
        "mcp_tool_call": "AST_TAINT_PII_TO_AGENTIC_SINK",
        "response": "AST_TAINT_PII_TO_RESPONSE",
        "db_write": "AST_TAINT_PII_TO_DB_WRITE",
    }.get(sink_kind, "AST_TAINT_PII_TO_UNKNOWN_SINK")


def _severity_for_sink(sink_kind: str) -> str:
    if sink_kind == "dormant_log":
        return "info"
    if sink_kind in {"llm_call", "mcp_tool_call", "external_http"}:
        return "high"
    if sink_kind == "log":
        return "high"
    if sink_kind == "db_write":
        return "medium"
    if sink_kind in {"command", "sql"}:
        return "critical"
    return "medium"


def _title_for_sink(sink_kind: str) -> str:
    return {
        "log": "AST taint: personal data may reach logs",
        "dormant_log": "Dormant debug log contains a personal-data path",
        "external_http": "AST taint: personal data may reach external HTTP",
        "llm_call": "AST taint: personal data may reach an LLM call",
        "mcp_tool_call": "AST taint: personal data may reach an MCP tool call",
        "response": "AST taint: personal data may reach a response",
        "db_write": "AST taint: personal data may be written to storage",
    }.get(sink_kind, "AST taint: personal data may reach a sink")


def _why_for_sink(sink_kind: str) -> str:
    if sink_kind in {"llm_call", "mcp_tool_call"}:
        return "Personal data crossing an agentic boundary can be copied into prompts, tool outputs, logs, or third-party processors."
    if sink_kind == "external_http":
        return "Personal data sent to external HTTP services needs documented purpose, minimization, and approval."
    if sink_kind == "log":
        return "Logs are often retained longer and copied into observability tools."
    if sink_kind == "dormant_log":
        return "The effective logger threshold currently blocks this call, but lowering the threshold would expose the data path."
    if sink_kind == "db_write":
        return "Storage creates retention, deletion, and access-control obligations."
    if sink_kind == "command":
        return "Request-controlled command execution can become remote code execution on the application host."
    if sink_kind == "sql":
        return "Request-controlled SQL structure can expose or modify the application database."
    return "Returning personal data can expose it to unauthenticated or overbroad clients."


def _recommendation_for_sink(sink_kind: str) -> str:
    if sink_kind in {"llm_call", "mcp_tool_call"}:
        return "Redact or minimize personal data before agentic calls, and record the approved tool/model purpose."
    if sink_kind == "external_http":
        return "Minimize fields, document the recipient, and require explicit consent or contractual basis before transfer."
    if sink_kind == "log":
        return "Log stable internal IDs or masked fields instead of raw request/user objects."
    if sink_kind == "dormant_log":
        return "Keep the production threshold restrictive and remove or redact the dormant raw-data debug statement before enabling verbose logging."
    if sink_kind == "db_write":
        return "Define retention/deletion controls and store only the fields required for the service."
    if sink_kind == "command":
        return "Use a fixed executable and allowlisted argument vector; never pass request data through a shell command string."
    if sink_kind == "sql":
        return "Use parameterized queries and keep request values out of SQL identifiers and query structure."
    return "Confirm the response is authenticated and field-minimized."


def _strip_js_ts_comments(lines: list[str]) -> list[str]:
    return list(_strip_js_ts_comments_cached(tuple(lines)))


@lru_cache(maxsize=512)
def _strip_js_ts_comments_cached(lines: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    in_block = False
    for line in lines:
        if not in_block and "//" not in line and "/*" not in line:
            result.append(line)
            continue
        output: list[str] = []
        quote: str | None = None
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
                    quote = None
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
def _js_ts_code_without_literals(line: str) -> str:
    """Blank quoted data while preserving executable template expressions."""

    output = [" "] * len(line)
    state = "code"
    quote_return = "code"
    escaped = False
    template_depth = 0
    index = 0
    while index < len(line):
        char = line[index]
        if state == "code":
            if char in {"'", '"'}:
                state = char
                quote_return = "code"
            elif char == "`":
                state = "template"
            else:
                output[index] = char
        elif state in {"'", '"'}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == state:
                state = quote_return
        elif state == "template":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "`":
                state = "code"
            elif char == "$" and index + 1 < len(line) and line[index + 1] == "{":
                output[index] = "$"
                output[index + 1] = "{"
                template_depth = 1
                state = "template_expression"
                index += 1
        else:  # template_expression
            if char in {"'", '"'}:
                state = char
                quote_return = "template_expression"
            else:
                output[index] = char
                if char == "{":
                    template_depth += 1
                elif char == "}":
                    template_depth -= 1
                    if template_depth == 0:
                        state = "template"
        index += 1
    return "".join(output)


@lru_cache(maxsize=16384)
def _js_ts_code_without_literals_or_regex(line: str) -> str:
    """Blank quoted values and likely regex literals while preserving offsets."""

    code = list(_js_ts_code_without_literals(line))
    rendered = "".join(code)
    index = 0
    while index < len(rendered):
        if rendered[index] != "/" or (
            index + 1 < len(rendered) and rendered[index + 1] in {"*", "/", "="}
        ):
            index += 1
            continue
        previous = index - 1
        while previous >= 0 and rendered[previous].isspace():
            previous -= 1
        previous_char = rendered[previous] if previous >= 0 else ""
        previous_word = ""
        if previous >= 0 and (
            rendered[previous].isalnum() or rendered[previous] in {"_", "$"}
        ):
            word_start = previous
            while word_start >= 0 and (
                rendered[word_start].isalnum()
                or rendered[word_start] in {"_", "$"}
            ):
                word_start -= 1
            previous_word = rendered[word_start + 1 : previous + 1]
        regex_prefix = (
            previous < 0
            or previous_char in "([{,;:=!?&|+-*%^~<>"
            or previous_word
            in {
                "await",
                "case",
                "delete",
                "do",
                "else",
                "in",
                "instanceof",
                "of",
                "return",
                "throw",
                "typeof",
                "void",
                "yield",
            }
        )
        if not regex_prefix:
            index += 1
            continue

        cursor = index + 1
        escaped = False
        in_character_class = False
        closing = -1
        while cursor < len(rendered):
            character = rendered[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "[":
                in_character_class = True
            elif character == "]" and in_character_class:
                in_character_class = False
            elif character == "/" and not in_character_class:
                closing = cursor
                break
            elif character in "\r\n":
                break
            cursor += 1
        if closing < 0:
            index += 1
            continue
        flag_end = closing + 1
        while flag_end < len(rendered) and rendered[flag_end].isalpha():
            flag_end += 1
        for offset in range(index, flag_end):
            code[offset] = " "
        index = flag_end
    return "".join(code)


_JS_TS_METHOD_BODY = re.compile(
    r"^\s*(?:(?:export|default|public|private|protected|static|abstract|override|async|get|set)\s+)*"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>{}]*>)?\s*\([^;{}]*\)\s*"
    r"(?::[^{};]+)?\s*\{"
)
_JS_TS_CONTROL_HEADS = {"catch", "do", "else", "finally", "for", "if", "switch", "try", "while", "with"}
_JS_TS_SCOPE_MARKER = re.compile(r"\bfunction\b|=>")
JS_TS_SCOPE_MARKER_LIMIT = 4096
JS_TS_SCOPE_SIGNATURE_WINDOW_CHARS = 8192
JS_TS_LOGICAL_STATEMENT_LIMIT = 10000


def _js_ts_body_for_scope_marker(text: str, marker: re.Match[str]) -> tuple[int, int] | None:
    """Locate a block-bodied function without applying a regex to a large source window."""

    if marker.group(0) == "=>":
        cursor = marker.end()
        limit = min(len(text), cursor + 256)
        while cursor < limit and text[cursor].isspace():
            cursor += 1
        return (marker.start(), cursor) if cursor < limit and text[cursor] == "{" else None

    limit = min(len(text), marker.end() + JS_TS_SCOPE_SIGNATURE_WINDOW_CHARS)
    cursor = marker.end()
    while cursor < limit and text[cursor] not in "({;":
        cursor += 1
    if cursor >= limit or text[cursor] != "(":
        return None

    paren_depth = 1
    cursor += 1
    while cursor < limit and paren_depth:
        if text[cursor] == "(":
            paren_depth += 1
        elif text[cursor] == ")":
            paren_depth -= 1
        cursor += 1
    if paren_depth:
        return None

    while cursor < limit:
        character = text[cursor]
        if character == "{":
            return marker.start(), cursor
        if character in ";=":
            return None
        cursor += 1
    return None


def _js_ts_function_scopes(
    lines: list[str] | tuple[str, ...],
) -> tuple[tuple[int, ...], dict[int, int | None], bool]:
    """Return each line's innermost function scope and its lexical parent map."""

    scope_ids, parent_items, scope_scan_limited = _js_ts_function_scopes_cached(tuple(lines))
    return scope_ids, dict(parent_items), scope_scan_limited


@lru_cache(maxsize=256)
def _js_ts_function_scopes_cached(
    lines: tuple[str, ...],
) -> tuple[tuple[int, ...], tuple[tuple[int, int | None], ...], bool]:

    if not lines:
        return (), ((0, None),), False
    code_lines = [_js_ts_code_without_literals(line) for line in lines]
    text = "\n".join(code_lines)
    line_starts: list[int] = []
    offset = 0
    for line in code_lines:
        line_starts.append(offset)
        offset += len(line) + 1

    braces: list[int] = []
    brace_pairs: dict[int, int] = {}
    for index, char in enumerate(text):
        if char == "{":
            braces.append(index)
        elif char == "}" and braces:
            brace_pairs[braces.pop()] = index

    markers: list[re.Match[str]] = []
    scope_scan_limited = False
    for marker in _JS_TS_SCOPE_MARKER.finditer(text):
        if len(markers) >= JS_TS_SCOPE_MARKER_LIMIT:
            scope_scan_limited = True
            break
        markers.append(marker)

    starts_by_open: dict[int, int] = {}
    for marker in markers:
        body = _js_ts_body_for_scope_marker(text, marker)
        if body is not None:
            start, open_brace = body
            starts_by_open[open_brace] = start
    for line_index, line in enumerate(code_lines):
        match = _JS_TS_METHOD_BODY.match(line)
        if not match or match.group("name").casefold() in _JS_TS_CONTROL_HEADS:
            continue
        open_relative = line.find("{", match.start(), match.end())
        if open_relative >= 0:
            starts_by_open[line_starts[line_index] + open_relative] = line_starts[line_index] + match.start()

    raw_ranges: list[tuple[int, int, int]] = []
    text_end = max(0, len(text) - 1)
    for open_brace, start in sorted(starts_by_open.items()):
        raw_ranges.append((start, open_brace, brace_pairs.get(open_brace, text_end)))

    body_starts = {start for start, _, _ in raw_ranges}
    for line_index, line in enumerate(code_lines):
        if "=>" not in line:
            continue
        line_start = line_starts[line_index]
        line_end = line_start + len(line)
        if any(line_start <= start <= line_end for start in body_starts):
            continue
        arrow = line.find("=>")
        raw_ranges.append((line_start + max(0, arrow - 1), line_start + arrow, line_end))

    assigned: list[tuple[int, int, int, int]] = []
    parents: dict[int, int | None] = {0: None}
    for scope_id, (start, open_brace, end) in enumerate(sorted(set(raw_ranges), key=lambda item: (item[1], item[2])), start=1):
        parent_candidates = [item for item in assigned if item[2] < open_brace <= item[3]]
        parent = max(parent_candidates, key=lambda item: item[2])[0] if parent_candidates else 0
        parents[scope_id] = parent
        assigned.append((scope_id, start, open_brace, end))

    line_scope_ids: list[int] = []
    for line_index, line_start in enumerate(line_starts):
        line_end = line_start + len(code_lines[line_index])
        active = [item for item in assigned if item[1] <= line_end and item[3] >= line_start]
        line_scope_ids.append(max(active, key=lambda item: item[2])[0] if active else 0)
    return tuple(line_scope_ids), tuple(parents.items()), scope_scan_limited


@lru_cache(maxsize=16384)
def _might_have_js_ts_sink(rendered: str) -> bool:
    return rendered.lstrip().startswith("return ") or any(hint in rendered for hint in JS_TS_SINK_HINTS)


def _js_ts_request_params(line: str) -> list[str]:
    return [name for name in _js_ts_declared_params(line) if _looks_like_request_name(name)]


def _js_ts_declared_params(line: str) -> list[str]:
    return list(_js_ts_declared_params_cached(line))


@lru_cache(maxsize=16384)
def _js_ts_declared_params_cached(line: str) -> tuple[str, ...]:
    groups: list[str] = []
    function_match = re.search(r"\bfunction\b[^{(]*\(([^)]*)\)|\b(?:GET|POST|PUT|PATCH|DELETE)\s*\(([^)]*)\)", line)
    if function_match:
        groups.extend(str(raw or "") for raw in function_match.groups())
    arrow_match = re.search(r"(?:\(([^)]*)\)|\b([A-Za-z_$][A-Za-z0-9_$]*)\b)\s*(?::[^=]+)?=>", line)
    if arrow_match:
        groups.extend(str(raw or "") for raw in arrow_match.groups())
    method_match = _JS_TS_METHOD_BODY.match(_js_ts_code_without_literals(line))
    if method_match and method_match.group("name").casefold() not in _JS_TS_CONTROL_HEADS:
        open_paren = line.find("(", method_match.start())
        close_paren = line.find(")", open_paren + 1)
        if open_paren >= 0 and close_paren > open_paren:
            groups.append(line[open_paren + 1 : close_paren])
    params: list[str] = []
    for raw in groups:
        for name in _js_ts_param_names(raw):
            if name not in params:
                params.append(name)
    return tuple(params)


@lru_cache(maxsize=16384)
def _js_ts_function_body_open(text: str) -> int:
    executable = _js_ts_code_without_literals(text)
    arrow = executable.find("=>")
    function = re.search(r"\bfunction\b", executable)
    if arrow >= 0 and (function is None or arrow < function.start()):
        tail = executable[arrow + 2 :]
        leading = len(tail) - len(tail.lstrip())
        candidate = arrow + 2 + leading
        return candidate if candidate < len(executable) and executable[candidate] == "{" else -1
    if function is None:
        return -1
    open_paren = executable.find("(", function.end())
    if open_paren < 0:
        return -1
    depth = 0
    close_paren = -1
    for index in range(open_paren, len(executable)):
        char = executable[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    if close_paren < 0:
        return -1
    return executable.find("{", close_paren + 1)


def _js_ts_assignment(line: str) -> tuple[list[str], str] | None:
    assignment = _js_ts_assignment_cached(line)
    if assignment is None:
        return None
    names, expression = assignment
    return list(names), expression


@lru_cache(maxsize=16384)
def _js_ts_assignment_cached(line: str) -> tuple[tuple[str, ...], str] | None:
    match = re.search(r"\b(?:const|let|var)\s+(.+?)\s*=\s*(.+?);?\s*$", line)
    if match:
        return tuple(_js_ts_target_names(match.group(1))), match.group(2)
    match = re.search(r"\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?)\s*=\s*(.+?);?\s*$", line)
    if match:
        return tuple(_js_ts_target_names(match.group(1))), match.group(2)
    return None


def _js_ts_target_names(target: str) -> list[str]:
    text = target.strip()
    if text.startswith("{") and "}" in text:
        names: list[str] = []
        for part in _js_ts_split_top_level(text[1 : text.rfind("}")]):
            rendered = part.strip().removeprefix("...").strip()
            colon = _js_ts_top_level_delimiter(rendered, ":")
            binding = rendered[colon + 1 :] if colon >= 0 else rendered
            default = _js_ts_top_level_delimiter(binding, "=")
            if default >= 0:
                binding = binding[:default]
            for name in _js_ts_target_names(binding):
                if name not in names:
                    names.append(name)
        return names
    if text.startswith("[") and "]" in text:
        names: list[str] = []
        for part in _js_ts_split_top_level(text[1 : text.rfind("]")]):
            rendered = part.strip().removeprefix("...").strip()
            default = _js_ts_top_level_delimiter(rendered, "=")
            if default >= 0:
                rendered = rendered[:default]
            for name in _js_ts_target_names(rendered):
                if name not in names:
                    names.append(name)
        return names
    type_separator = _js_ts_top_level_delimiter(text, ":")
    if type_separator >= 0:
        text = text[:type_separator].strip()
    default_separator = _js_ts_top_level_delimiter(text, "=")
    if default_separator >= 0:
        text = text[:default_separator].strip()
    return [text] if JS_TS_IDENT.fullmatch(text) else []


def _js_ts_split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closers = {")": "(", "]": "[", "}": "{"}
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in depths:
            depths[char] += 1
            continue
        if char in closers:
            opener = closers[char]
            depths[opener] = max(0, depths[opener] - 1)
            continue
        if char == delimiter and not any(depths.values()):
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _js_ts_top_level_delimiter(text: str, delimiter: str) -> int:
    parts = _js_ts_split_top_level(text, delimiter)
    return len(parts[0]) if len(parts) > 1 else -1


def _js_ts_names(text: str) -> list[str]:
    return list(_js_ts_names_cached(text))


@lru_cache(maxsize=16384)
def _js_ts_names_cached(text: str) -> tuple[str, ...]:
    return tuple(JS_TS_IDENT.findall(text))


@lru_cache(maxsize=16384)
def _js_ts_source_kind(text: str) -> str | None:
    rendered = text.lower()
    if any(
        term in rendered
        for term in (
            "req.body",
            "request.body",
            "req.json",
            "request.json",
            "formdata(",
            "req.params",
            "request.params",
            "params.",
            "req.query",
            "request.query",
            "searchparams",
            "req.cookies",
            "request.cookies",
            "request.nexturl",
        )
    ):
        return "request_body"
    if "process.env" in rendered or "import.meta.env" in rendered:
        return "env"
    if any(term in rendered for term in (".findunique(", ".findmany(", ".findfirst(", ".query(", ".execute(", "select ")):
        return "db_read"
    if any(term in rendered for term in ("localstorage", "sessionstorage", "cookies().get")):
        return "storage"
    return None


@lru_cache(maxsize=16384)
def _js_ts_source_is_sensitive(source_kind: str, text: str) -> bool:
    if source_kind == "env":
        names = [
            next(part for part in match.groups() if part is not None)
            for match in re.finditer(
                r"(?:process|import\.meta)\.env(?:\.([A-Za-z_$][A-Za-z0-9_$]*)|\[['\"]([^'\"]+)['\"]\])",
                text,
                re.IGNORECASE,
            )
        ]
        if names:
            return any(_field_is_sensitive(name) for name in names)
        return bool(re.search(r"(?:process|import\.meta)\.env\b", text, re.IGNORECASE))
    return source_kind in {"request_body", "db_read"} or bool(SENSITIVE_NAME.search(text))


@lru_cache(maxsize=16384)
def _js_ts_reference_is_sensitive(text: str, name: str) -> bool:
    pattern = re.compile(
        rf"\b{re.escape(name)}\b((?:(?:\.|\?\.)[A-Za-z_$][A-Za-z0-9_$]*)+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        fields = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", match.group(1))
        if any(_field_is_sensitive(field) for field in fields):
            return True
    return False


def _js_ts_source_relevant_for_sink(source: TaintSource, sink_kind: str) -> bool:
    if source.sensitive or sink_kind in {"llm_call", "mcp_tool_call", "external_http"}:
        return True
    return source.kind in {"request_arg", "request_body"} and sink_kind in {"command", "sql"}


def _js_ts_statement_end(code: str, start: int) -> int:
    limit = min(len(code), start + JS_TS_LOGICAL_STATEMENT_LIMIT)
    depths = {"(": 0, "[": 0, "{": 0}
    closers = {")": "(", "]": "[", "}": "{"}
    last_significant = ""
    for position in range(start, limit):
        character = code[position]
        if character in depths:
            depths[character] += 1
        elif character in closers and depths[closers[character]] > 0:
            depths[closers[character]] -= 1
        elif character == ";" and not any(depths.values()):
            return position + 1
        elif character == "\n" and not any(depths.values()):
            if last_significant not in {
                "",
                "!",
                "%",
                "&",
                "(",
                "*",
                "+",
                ",",
                "-",
                ".",
                "/",
                ":",
                "<",
                "=",
                ">",
                "?",
                "[",
                "^",
                "{",
                "|",
                "~",
            }:
                return position
        if not character.isspace():
            last_significant = character
    return limit


def _js_ts_receiver_identifier(expression: str) -> str | None:
    rendered = expression.strip().rstrip(";,").strip()
    for _ in range(16):
        if rendered.endswith("!"):
            rendered = rendered[:-1].rstrip()
            continue
        if rendered.startswith("(") and rendered.endswith(")"):
            depth = 0
            closes_outer = False
            for index, character in enumerate(rendered):
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                    if depth == 0:
                        closes_outer = index == len(rendered) - 1
                        break
            if closes_outer:
                rendered = rendered[1:-1].strip()
                continue
        assertion = re.fullmatch(
            r"(?P<base>.+?)\s+(?:as|satisfies)\s+"
            r"[A-Za-z_$][A-Za-z0-9_$<>{}\[\]|&.,\s]*",
            rendered,
        )
        if assertion:
            rendered = assertion.group("base").strip()
            continue
        break
    return rendered if JS_TS_IDENT.fullmatch(rendered) else None


def _js_ts_receiver_before_member(
    code: str,
    member_start: int,
) -> tuple[str, int] | None:
    cursor = member_start - 1
    while cursor >= 0 and code[cursor].isspace():
        cursor -= 1
    while cursor >= 0 and code[cursor] == "!":
        cursor -= 1
        while cursor >= 0 and code[cursor].isspace():
            cursor -= 1
    if cursor < 0:
        return None

    if code[cursor] == ")":
        depth = 1
        start = cursor - 1
        while start >= 0 and depth:
            if code[start] == ")":
                depth += 1
            elif code[start] == "(":
                depth -= 1
            start -= 1
        if depth:
            return None
        start += 1
        expression = code[start : cursor + 1]
    else:
        end = cursor + 1
        while cursor >= 0 and (
            code[cursor].isalnum() or code[cursor] in {"_", "$"}
        ):
            cursor -= 1
        start = cursor + 1
        expression = code[start:end]

    name = _js_ts_receiver_identifier(expression)
    if not name:
        return None
    previous = start - 1
    while previous >= 0 and code[previous].isspace():
        previous -= 1
    if previous >= 0 and code[previous] in {".", "?"}:
        return None
    return name, start


def _js_ts_command_bindings(text: str) -> JsTsCommandBindings:
    analysis_lines = _strip_js_ts_comments(text.splitlines())
    if not analysis_lines:
        return JsTsCommandBindings()
    uncommented = "\n".join(analysis_lines)
    code_only = _js_ts_code_without_literals_or_regex(uncommented)
    line_starts: list[int] = []
    offset = 0
    for line in analysis_lines:
        line_starts.append(offset)
        offset += len(line) + 1
    source_length = len(code_only)
    global_scope = _JsTsBindingScope(0, source_length, 0)

    brace_stack: list[tuple[int, int]] = []
    brace_pairs: dict[int, int] = {}
    block_scopes: list[_JsTsBindingScope] = []
    for position, character in enumerate(code_only):
        if character == "{":
            brace_stack.append((position, len(brace_stack) + 1))
        elif character == "}" and brace_stack:
            start, depth = brace_stack.pop()
            brace_pairs[start] = position
            block_scopes.append(_JsTsBindingScope(start, position, depth))
    for start, depth in brace_stack:
        block_scopes.append(
            _JsTsBindingScope(start, max(start, source_length), depth)
        )

    def lexical_scope_for_offset(position: int) -> _JsTsBindingScope:
        candidates = [
            scope
            for scope in block_scopes
            if scope.start < position <= scope.end
        ]
        return max(
            candidates,
            key=lambda scope: (scope.depth, scope.start, -scope.end),
            default=global_scope,
        )

    function_scopes: list[tuple[_JsTsBindingScope, str]] = []
    seen_function_scopes: set[tuple[int, int]] = set()
    for marker in _JS_TS_SCOPE_MARKER.finditer(code_only):
        body = _js_ts_body_for_scope_marker(code_only, marker)
        if body is not None:
            start, open_brace = body
            end = brace_pairs.get(open_brace, source_length)
            block_scope = next(
                (
                    scope
                    for scope in block_scopes
                    if scope.start == open_brace and scope.end == end
                ),
                lexical_scope_for_offset(open_brace),
            )
            key = (start, end)
            if key not in seen_function_scopes:
                seen_function_scopes.add(key)
                function_scopes.append(
                    (
                        _JsTsBindingScope(start, end, block_scope.depth),
                        code_only[start:open_brace],
                    )
                )
        elif marker.group(0) == "=>":
            line_index = max(0, bisect_right(line_starts, marker.start()) - 1)
            start = line_starts[line_index]
            end = (
                line_starts[line_index + 1] - 1
                if line_index + 1 < len(line_starts)
                else source_length
            )
            parent = lexical_scope_for_offset(marker.start())
            key = (start, end)
            if key not in seen_function_scopes:
                seen_function_scopes.add(key)
                function_scopes.append(
                    (
                        _JsTsBindingScope(start, end, parent.depth + 1),
                        code_only[start : marker.end()],
                    )
                )
    for line_index, line in enumerate(
        _js_ts_code_without_literals_or_regex(item)
        for item in analysis_lines
    ):
        method = _JS_TS_METHOD_BODY.match(line)
        if not method or method.group("name").casefold() in _JS_TS_CONTROL_HEADS:
            continue
        open_relative = line.find("{", method.start(), method.end())
        if open_relative < 0:
            continue
        open_brace = line_starts[line_index] + open_relative
        end = brace_pairs.get(open_brace, source_length)
        key = (line_starts[line_index] + method.start(), end)
        if key in seen_function_scopes:
            continue
        seen_function_scopes.add(key)
        block_scope = lexical_scope_for_offset(open_brace + 1)
        function_scopes.append(
            (
                _JsTsBindingScope(key[0], end, block_scope.depth),
                code_only[key[0] : open_brace],
            )
        )

    def function_scope_for_offset(position: int) -> _JsTsBindingScope:
        return max(
            (
                scope
                for scope, _signature in function_scopes
                if scope.contains(position)
            ),
            key=lambda scope: (scope.depth, scope.start, -scope.end),
            default=global_scope,
        )

    patterns = (
        (
            "import",
            re.compile(
                rf"\bimport\s+(?:\*\s+as\s+)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
                rf"\s+from\s+(?:{_JS_TS_COMMAND_MODULE_LITERAL})"
            ),
        ),
        (
            "import",
            re.compile(
                rf"\bimport\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
                rf"require\s*\(\s*(?:{_JS_TS_COMMAND_MODULE_LITERAL})\s*\)"
            ),
        ),
        (
            "declaration",
            re.compile(
                rf"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
                rf"(?:\s*:[^=;\n]+)?\s*=\s*(?:await\s+)?(?:require|import)\s*"
                rf"\(\s*(?:{_JS_TS_COMMAND_MODULE_LITERAL})\s*\)"
            ),
        ),
        (
            "assignment",
            re.compile(
                rf"(?<![A-Za-z0-9_$.\]])(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
                rf"\s*=\s*(?:await\s+)?(?:require|import)\s*"
                rf"\(\s*(?:{_JS_TS_COMMAND_MODULE_LITERAL})\s*\)"
            ),
        ),
    )
    matches: list[tuple[int, str, re.Match[str]]] = []
    for kind, pattern in patterns:
        for match in pattern.finditer(uncommented):
            if code_only[match.start() : match.start() + 1].strip():
                matches.append((match.start(), kind, match))

    _bare_pattern, member_pattern, _inline_require = _js_ts_process_sink_patterns(
        JS_TS_PROCESS_METHODS
    )
    member_queries: list[tuple[str, int]] = []
    receiver_names: set[str] = set()
    for member in member_pattern.finditer(code_only):
        receiver = _js_ts_receiver_before_member(code_only, member.start())
        if receiver is None:
            continue
        receiver_names.add(receiver[0])
        member_queries.append(receiver)
    candidate_names = (
        {match.group("name") for _, _, match in matches} | receiver_names
    )
    events: list[_JsTsBindingEvent] = []
    events_by_name: dict[str, list[_JsTsBindingEvent]] = {}
    timeline_activations: dict[
        str,
        dict[_JsTsBindingScope, list[int]],
    ] = {}
    timeline_states: dict[
        str,
        dict[_JsTsBindingScope, list[bool]],
    ] = {}
    event_order = 0

    def append_event(
        name: str,
        scope: _JsTsBindingScope,
        activation: int,
        is_command: bool,
    ) -> None:
        nonlocal event_order
        event_order += 1
        event = _JsTsBindingEvent(
            name=name,
            scope=scope,
            activation=max(scope.start, activation),
            order=event_order,
            is_command=is_command,
        )
        events.append(event)
        events_by_name.setdefault(name, []).append(event)
        activations = timeline_activations.setdefault(name, {}).setdefault(
            scope,
            [],
        )
        states = timeline_states.setdefault(name, {}).setdefault(scope, [])
        if not activations or event.activation >= activations[-1]:
            activations.append(event.activation)
            states.append(event.is_command)
        else:
            index = bisect_right(activations, event.activation)
            activations.insert(index, event.activation)
            states.insert(index, event.is_command)

    def active_scope_for(name: str, position: int) -> _JsTsBindingScope | None:
        applicable = [
            scope
            for scope, activations in timeline_activations.get(name, {}).items()
            if activations
            and activations[0] <= position
            and scope.contains(position)
        ]
        if not applicable:
            return None
        return max(
            applicable,
            key=lambda scope: (scope.depth, scope.start, -scope.end),
        )

    def is_command_at(name: str, position: int) -> bool:
        scope = active_scope_for(name, position)
        if scope is None:
            return False
        activations = timeline_activations[name][scope]
        index = bisect_right(activations, position) - 1
        return index >= 0 and timeline_states[name][scope][index]

    command_declarations: list[tuple[str, int, int]] = []
    command_assignments: list[tuple[str, int, int]] = []
    for start, kind, match in sorted(matches, key=lambda item: (item[0], item[1])):
        name = match.group("name")
        if kind == "import":
            append_event(name, global_scope, 0, True)
        elif kind == "declaration":
            command_declarations.append((name, start, match.end()))
        else:
            command_assignments.append((name, start, match.end()))
    direct_declarations_by_name: dict[str, list[tuple[int, int]]] = {}
    direct_assignments_by_name: dict[str, list[tuple[int, int]]] = {}
    for name, start, end in command_declarations:
        direct_declarations_by_name.setdefault(name, []).append((start, end))
    for name, start, end in command_assignments:
        direct_assignments_by_name.setdefault(name, []).append((start, end))

    declaration_pattern = re.compile(
        r"\b(?P<kind>const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    declarations: list[tuple[re.Match[str], int]] = []
    for declaration in declaration_pattern.finditer(code_only):
        name = declaration.group("name")
        if name not in candidate_names:
            continue
        end = _js_ts_statement_end(code_only, declaration.end())
        declarations.append((declaration, end))
        scope = (
            function_scope_for_offset(declaration.start())
            if declaration.group("kind") == "var"
            else lexical_scope_for_offset(declaration.start())
        )
        append_event(name, scope, scope.start, False)

    for scope, signature in function_scopes:
        for name in set(_js_ts_declared_params(signature)) & candidate_names:
            append_event(name, scope, scope.start, False)

    shadow_declaration = re.compile(
        r"\b(?:async\s+)?(?:function|class)\s+"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    for shadow in shadow_declaration.finditer(code_only):
        name = shadow.group("name")
        if name in candidate_names:
            scope = lexical_scope_for_offset(shadow.start())
            append_event(name, scope, scope.start, False)

    catch_pattern = re.compile(
        r"\bcatch\s*\(\s*(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    for catch in catch_pattern.finditer(code_only):
        name = catch.group("name")
        if name in candidate_names:
            scope = lexical_scope_for_offset(catch.start())
            append_event(name, scope, scope.start, False)

    declaration_ranges = [
        (declaration.start(), end) for declaration, end in declarations
    ]
    declaration_starts = [start for start, _end in declaration_ranges]

    def inside_declaration(position: int) -> bool:
        index = bisect_right(declaration_starts, position) - 1
        return (
            index >= 0
            and declaration_ranges[index][0]
            <= position
            <= declaration_ranges[index][1]
        )

    assignment_pattern = re.compile(
        r"(?<![A-Za-z0-9_$.\]])"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=(?!=|>)"
    )
    operations: list[tuple[int, str, str, int, int, _JsTsBindingScope | None]] = []
    for declaration, end in declarations:
        name = declaration.group("name")
        equals = code_only.find("=", declaration.end(), end)
        if equals >= 0:
            scope = (
                function_scope_for_offset(declaration.start())
                if declaration.group("kind") == "var"
                else lexical_scope_for_offset(declaration.start())
            )
            operations.append(
                (declaration.start(), "declaration", name, equals + 1, end, scope)
            )
    for assignment in assignment_pattern.finditer(code_only):
        name = assignment.group("name")
        if name not in candidate_names or inside_declaration(assignment.start()):
            continue
        end = _js_ts_statement_end(code_only, assignment.end())
        operations.append(
            (
                assignment.start(),
                "assignment",
                name,
                assignment.end(),
                end,
                None,
            )
        )

    for start, kind, name, expression_start, end, declared_scope in sorted(
        operations,
        key=lambda item: item[0],
    ):
        direct_ranges = (
            direct_declarations_by_name.get(name, ())
            if kind == "declaration"
            else direct_assignments_by_name.get(name, ())
        )
        direct = next(
            (
                match_end
                for match_start, match_end in direct_ranges
                if start <= match_start <= end
            ),
            None,
        )
        scope = declared_scope or active_scope_for(name, start)
        function_scope = function_scope_for_offset(start)
        if (
            scope is None
            or (scope == global_scope and function_scope != global_scope)
        ):
            scope = function_scope
        if direct is not None:
            append_event(name, scope, direct, True)
            continue
        alias = _js_ts_receiver_identifier(
            code_only[expression_start:end].strip().rstrip(";")
        )
        append_event(
            name,
            scope,
            end,
            bool(alias and is_command_at(alias, expression_start)),
        )

    timeline_index = {
        name: tuple(
            _JsTsBindingTimeline(
                scope=scope,
                activations=tuple(activations),
                command_states=tuple(timeline_states[name][scope]),
            )
            for scope, activations in sorted(
                scopes.items(),
                key=lambda item: (
                    item[0].start,
                    item[0].end,
                    item[0].depth,
                ),
            )
        )
        for name, scopes in timeline_activations.items()
    }
    return JsTsCommandBindings(
        namespaces=frozenset(candidate_names),
        line_starts=tuple(line_starts),
        source_length=source_length,
        events=tuple(events),
        event_index={
            name: tuple(name_events)
            for name, name_events in events_by_name.items()
        },
        timeline_index=timeline_index,
        position_index=_js_ts_command_position_index(
            timeline_index,
            member_queries,
        ),
    )


def _js_ts_command_position_index(
    timeline_index: dict[str, tuple[_JsTsBindingTimeline, ...]],
    member_queries: list[tuple[str, int]],
) -> dict[tuple[str, int], bool]:
    queries_by_name: dict[str, set[int]] = {}
    for name, position in member_queries:
        queries_by_name.setdefault(name, set()).add(position)

    resolved: dict[tuple[str, int], bool] = {}
    for name, query_positions in queries_by_name.items():
        timelines = sorted(
            (
                timeline
                for timeline in timeline_index.get(name, ())
                if timeline.activations
            ),
            key=lambda timeline: (
                timeline.activations[0],
                timeline.scope.start,
                timeline.scope.end,
                timeline.scope.depth,
            ),
        )
        active: list[
            tuple[int, int, int, int, _JsTsBindingTimeline]
        ] = []
        timeline_index_cursor = 0
        for position in sorted(query_positions):
            while (
                timeline_index_cursor < len(timelines)
                and timelines[timeline_index_cursor].activations[0] <= position
            ):
                timeline = timelines[timeline_index_cursor]
                heapq.heappush(
                    active,
                    (
                        -timeline.scope.depth,
                        -timeline.scope.start,
                        timeline.scope.end,
                        timeline_index_cursor,
                        timeline,
                    ),
                )
                timeline_index_cursor += 1
            while active and active[0][4].scope.end < position:
                heapq.heappop(active)
            if not active:
                resolved[(name, position)] = False
                continue
            timeline = active[0][4]
            activation_index = (
                bisect_right(timeline.activations, position) - 1
            )
            resolved[(name, position)] = (
                activation_index >= 0
                and timeline.command_states[activation_index]
            )
    return resolved


def _js_ts_has_process_sink(
    rendered: str,
    bindings: JsTsCommandBindings | None = None,
    methods: frozenset[str] = JS_TS_COMMAND_METHODS,
    line_no: int | None = None,
    column_offset: int = 0,
) -> bool:
    bindings = bindings or JsTsCommandBindings()
    code_only = _js_ts_code_without_literals_or_regex(rendered)
    bare_pattern, member_pattern, inline_require = _js_ts_process_sink_patterns(methods)
    for match in bare_pattern.finditer(code_only):
        previous = match.start() - 1
        while previous >= 0 and code_only[previous].isspace():
            previous -= 1
        if previous < 0 or code_only[previous] not in {".", "?"}:
            return True

    for match in member_pattern.finditer(code_only):
        receiver = _js_ts_receiver_before_member(code_only, match.start())
        if receiver is None:
            continue
        receiver_name, receiver_start = receiver
        precise_column = (
            column_offset + receiver_start if "\n" not in rendered else None
        )
        if bindings.is_command(receiver_name, line_no, precise_column):
            return True

    return any(
        code_only[match.start() : match.start() + 1].strip()
        for match in inline_require.finditer(rendered)
    )


@lru_cache(maxsize=4)
def _js_ts_process_sink_patterns(
    methods: frozenset[str],
) -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    method_pattern = "|".join(
        sorted((re.escape(method) for method in methods), key=len, reverse=True)
    )
    return (
        re.compile(rf"(?<![A-Za-z0-9_$?.])(?:{method_pattern})\s*\("),
        re.compile(
            rf"(?:\?\.|\.)\s*(?:{method_pattern})\s*\("
        ),
        re.compile(
            rf"\brequire\s*\(\s*(?:{_JS_TS_COMMAND_MODULE_LITERAL})\s*\)"
            rf"\s*(?:\.\s*|\?\.\s*)(?:{method_pattern})\s*\("
        ),
    )


def _js_ts_sink_kind(
    line: str,
    command_bindings: JsTsCommandBindings = JsTsCommandBindings(),
    line_no: int | None = None,
    column_offset: int = 0,
) -> str | None:
    rendered = line.lower()
    if _js_ts_has_process_sink(
        line,
        command_bindings,
        line_no=line_no,
        column_offset=column_offset,
    ):
        return "command"
    if any(term in rendered for term in (".query(", ".execute(", ".raw(", "$queryraw", "$executeraw")):
        return "sql"
    if re.search(r"\bconsole\.(log|info|debug|warn|error)\s*\(", rendered) or "logger." in rendered:
        return "log"
    if any(term in rendered for term in ("fetch(", "axios.", "ky(", "got(")):
        return "external_http"
    if any(term in rendered for term in ("openai", "anthropic", "gemini", "chat.completions", "responses.create", "generatecontent")):
        return "llm_call"
    if any(term in rendered for term in ("calltool", "call_tool", "usemcptool", "use_mcp_tool", "clientsession")):
        return "mcp_tool_call"
    if any(term in rendered for term in ("response.json", "nextresponse.json", "res.json", "reply.send")) or rendered.strip().startswith("return "):
        return "response"
    if any(term in rendered for term in (".create(", ".update(", ".insert(", ".upsert(", ".save(")):
        return "db_write"
    return None


@lru_cache(maxsize=16384)
def _js_ts_sink_relevant_expression(rendered: str, sink_kind: str) -> str:
    if sink_kind == "sql":
        return _js_ts_sql_structure_expression(rendered)
    if sink_kind == "command":
        return _js_ts_command_structure_expression(rendered)
    return rendered


def _js_ts_sql_structure_expression(rendered: str) -> str:
    lowered = rendered.casefold()
    if re.search(r"\$(?:query|execute)raw\s*`", lowered) and "rawunsafe" not in lowered:
        return ""
    first = _js_ts_first_call_argument(
        rendered,
        (".query(", ".execute(", ".raw(", "$queryrawunsafe(", "$executerawunsafe(", "$queryraw(", "$executeraw("),
    )
    stripped = first.strip()
    if stripped.startswith("{"):
        body = stripped[1 : stripped.rfind("}")] if "}" in stripped else stripped[1:]
        for part in _js_ts_split_top_level(body):
            separator = _js_ts_top_level_delimiter(part, ":")
            if separator < 0:
                continue
            key = part[:separator].strip().strip("'\"").casefold()
            if key in {"text", "sql", "query"}:
                return part[separator + 1 :]
    return first


def _js_ts_command_structure_expression(rendered: str) -> str:
    lowered = rendered.casefold()
    if "shell:" in lowered and re.search(r"\bshell\s*:\s*true\b", lowered):
        return rendered
    marker_positions = [
        (lowered.find(marker), marker)
        for marker in ("exec(", "execsync(", "spawn(", "spawnsync(")
        if lowered.find(marker) >= 0
    ]
    if not marker_positions:
        return rendered
    _, marker = min(marker_positions, key=lambda item: item[0])
    first = _js_ts_first_call_argument(rendered, (marker,))
    if marker in {"spawn(", "spawnsync("}:
        literal = first.strip().strip("'\"").casefold()
        if literal in {"bash", "cmd", "cmd.exe", "dash", "fish", "ksh", "powershell", "pwsh", "sh", "zsh"}:
            return rendered
    return first


def _js_ts_first_call_argument(rendered: str, markers: tuple[str, ...]) -> str:
    lowered = rendered.casefold()
    starts = [(lowered.find(marker), marker) for marker in markers if lowered.find(marker) >= 0]
    if not starts:
        return rendered
    start, marker = min(starts, key=lambda item: item[0])
    index = start + len(marker)
    depth = 0
    quote: str | None = None
    escaped = False
    for cursor in range(index, len(rendered)):
        char = rendered[cursor]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}" and depth > 0:
            depth -= 1
            continue
        if (char == "," or char == ")") and depth == 0:
            return rendered[index:cursor]
    return rendered[index:]


def _js_ts_rule_id_for_sink(sink_kind: str) -> str:
    return {
        "log": "JS_TS_TAINT_PII_TO_LOG",
        "external_http": "JS_TS_TAINT_PII_TO_EXTERNAL_HTTP",
        "llm_call": "JS_TS_TAINT_PII_TO_AGENTIC_SINK",
        "mcp_tool_call": "JS_TS_TAINT_PII_TO_AGENTIC_SINK",
        "response": "JS_TS_TAINT_PII_TO_RESPONSE",
        "db_write": "JS_TS_TAINT_PII_TO_DB_WRITE",
        "command": "WEB_UNTRUSTED_INPUT_TO_COMMAND",
        "sql": "WEB_UNTRUSTED_INPUT_TO_SQL",
    }.get(sink_kind, "JS_TS_TAINT_PII_TO_UNKNOWN_SINK")


def _js_ts_title_for_sink(sink_kind: str) -> str:
    return {
        "log": "JS/TS taint: personal data may reach logs",
        "external_http": "JS/TS taint: personal data may reach external HTTP",
        "llm_call": "JS/TS taint: personal data may reach an LLM call",
        "mcp_tool_call": "JS/TS taint: personal data may reach an MCP tool call",
        "response": "JS/TS taint: personal data may reach a response",
        "db_write": "JS/TS taint: personal data may be written to storage",
        "command": "JS/TS taint: request data may reach command execution",
        "sql": "JS/TS taint: request data may reach SQL execution",
    }.get(sink_kind, "JS/TS taint: personal data may reach a sink")


def _js_ts_has_next_route_surface(path: Path, rendered: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return (
        "/app/api/" in normalized
        or "/pages/api/" in normalized
        or normalized.endswith("/route.ts")
        or normalized.endswith("/route.js")
        or bool(re.search(r"\bexport\s+async\s+function\s+(get|post|put|patch|delete)\b", rendered))
    )


def _js_ts_has_route_or_action_surface(path: Path, rendered: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return _js_ts_has_next_route_surface(path, rendered) or _js_ts_has_server_action(rendered) or any(term in rendered for term in ("express()", "router.", "app.get(", "app.post("))


def _js_ts_has_server_action(rendered: str) -> bool:
    return "'use server'" in rendered or '"use server"' in rendered


def _js_ts_has_data_or_response(rendered: str) -> bool:
    return any(
        term in rendered
        for term in (
            "request.json",
            "request.nexturl",
            "params.",
            "searchparams",
            "cookies().get",
            ".findunique(",
            ".findfirst(",
            ".findmany(",
            ".from(",
            ".collection(",
            ".query(",
            ".execute(",
            "select ",
        )
    )


def _js_ts_has_mutation(rendered: str) -> bool:
    return any(term in rendered for term in (".insert(", ".update(", ".delete(", ".upsert(", ".create(", ".set(", ".save("))


def _js_ts_has_auth_guard(rendered: str) -> bool:
    rendered = _js_ts_code_without_strings(rendered)
    call_patterns = (
        r"\bgetserversession\s*\(",
        r"\bauth\s*\(",
        r"\bcurrentuser\s*\(",
        r"\bgetuser\s*\(",
        r"\bsupabase\.auth\.getuser\s*\(",
        r"\bclerkclient\s*\(",
        r"\bwithauth\s*\(",
        r"\brequireauth\s*\(",
        r"\brequire_auth\s*\(",
        r"\bverifyidtoken\s*\(",
        r"\bverifytoken\s*\(",
    )
    property_patterns = (r"\breq\.user\b", r"\brequest\.user\b", r"\bcontext\.user\b", r"\bctx\.user\b", r"\bsession\.user\b")
    return any(re.search(pattern, rendered) for pattern in (*call_patterns, *property_patterns))


def _js_ts_has_effective_auth_guard(rendered: str, untrusted_helpers: set[str] | None = None) -> bool:
    code = _js_ts_code_without_strings(rendered)
    untrusted = {name.casefold() for name in (untrusted_helpers or set())}
    call_pattern = re.compile(
        r"\b(getserversession|auth|currentuser|getuser|withauth|requireauth|require_auth|verifyidtoken|verifytoken)\s*\(|"
        r"\bsupabase\.auth\.getuser\s*\(|\bclerkclient\s*\(",
        re.IGNORECASE,
    )
    sensitive = re.search(
        r"request\.json\s*\(|request\.nexturl|params\.|searchparams|cookies\(\)\.get|"
        r"\.find(?:unique|first|many|byid)\s*\(|\.from\s*\(|\.collection\s*\(|\.query\s*\(|\.execute\s*\(|"
        r"\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.create\s*\(|\.set\s*\(|\.save\s*\(|"
        r"(?:next)?response\.json\s*\(|\bres\.json\s*\(",
        code,
        re.IGNORECASE,
    )
    sensitive_position = sensitive.start() if sensitive is not None else len(code)
    for match in call_pattern.finditer(code):
        name = str(match.group(1) or match.group(0).split("(", 1)[0]).casefold()
        line_prefix = code[code.rfind("\n", 0, match.start()) + 1 : match.start()]
        if (
            re.search(r"\bfunction\s+$", line_prefix)
            or name in untrusted
            or _js_ts_position_is_obviously_unreachable(code, match.start())
            or match.start() >= sensitive_position
        ):
            continue
        if name in {"requireauth", "require_auth", "verifyidtoken", "verifytoken", "withauth"}:
            return True
        line_start = code.rfind("\n", 0, match.start()) + 1
        assignment_prefix = code[line_start : match.start()]
        assignment = re.search(r"\b(?:const|let|var)\s+(.+?)\s*=\s*(?:await\s*)?$", assignment_prefix, re.IGNORECASE)
        if assignment and _js_ts_identity_binding_is_enforced(
            code,
            match.end(),
            _js_ts_target_names(assignment.group(1)),
            sensitive_position,
        ):
            return True
    for identity in ("req.user", "request.user", "context.user", "ctx.user", "session.user"):
        identity_match = re.search(rf"\b{re.escape(identity)}\b", code, re.IGNORECASE)
        if identity_match and identity_match.start() < sensitive_position and _js_ts_identity_reference_is_enforced(code, identity):
            return True
    return False


def _js_ts_position_is_obviously_unreachable(code: str, position: int) -> bool:
    line_start = code.rfind("\n", 0, position) + 1
    prefix = code[line_start:position]
    if re.search(r"\bif\s*\(\s*false\s*\)[^{;]*$|\bfalse\s*&&[^;]*$", prefix, re.IGNORECASE):
        return True
    before = code[:position]
    for match in reversed(list(re.finditer(r"\bif\s*\(\s*false\s*\)\s*\{", before, re.IGNORECASE))):
        body = _extract_braced_body(code, match.end() - 1)
        if match.end() - 1 + len(body) >= position:
            return True
    return False


def _js_ts_identity_binding_is_enforced(code: str, call_end: int, names: list[str], sensitive_position: int) -> bool:
    if not names:
        return False
    tail = code[call_end:]
    for name in names:
        escaped = re.escape(name)
        reject = re.search(
            rf"\bif\s*\(\s*!\s*{escaped}(?:\s*\?\.[A-Za-z_$][A-Za-z0-9_$]*)?\s*\)\s*(?:\{{)?[\s\S]{{0,240}}?\b(?:return|throw|redirect)\b",
            tail,
            re.IGNORECASE,
        )
        if reject:
            return True
        identity_use = re.search(
            rf"\b{escaped}\s*(?:\?\.)?\.\s*(?:user\s*(?:\?\.)?\.\s*)?(?:id|sub|uid|email|role)\b",
            tail,
            re.IGNORECASE,
        )
        if identity_use and call_end + identity_use.start() <= max(sensitive_position + 1200, call_end):
            return True
    return False


def _js_ts_identity_reference_is_enforced(code: str, identity: str) -> bool:
    escaped = re.escape(identity)
    if re.search(
        rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*(?:\{{)?[\s\S]{{0,240}}?\b(?:return|throw|redirect)\b",
        code,
        re.IGNORECASE,
    ):
        return True
    return bool(re.search(rf"\b{escaped}\s*(?:\?\.)?\.\s*(?:id|sub|uid|email|role)\b", code, re.IGNORECASE))


def _js_ts_helper_enforces_auth(body: str) -> bool:
    return bool(
        re.search(r"\bthrow\b|\bredirect\s*\(|\b(?:unauthorized|forbidden)\b|\breturn\s+[^;\n]*(?:401|403)\b", body)
        or re.search(r"\b(?:jwt\.)?verify\s*\(|\bverifyidtoken\s*\(|\bsupabase\.auth\.getuser\s*\(", body)
        or re.search(r"\bif\s*\(\s*!\s*(?:req|request|session|user)[^)]*\)[\s\S]{0,160}\b(?:return|throw|redirect)\b", body)
    )


def _js_ts_ownership_is_bound_to_data_access(rendered: str) -> bool:
    code = _js_ts_code_without_strings(rendered).casefold()
    owner_pattern = re.compile(
        r"\b(?:user_?id|owner_?id|tenant_?id|team_?id|organization_?id|org_?id)\b\s*(?::|=)|"
        r"\.eq\s*\(\s*['\"](?:user_?id|owner_?id|tenant_?id|team_?id|organization_?id|org_?id)['\"]",
        re.IGNORECASE,
    )
    data_pattern = re.compile(
        r"\.find(?:unique|first|many|byid)\s*\(|\.from\s*\(|\.collection\s*\(|\.doc\s*\(|\.query\s*\(|\.execute\s*\(",
        re.IGNORECASE,
    )
    for match in data_pattern.finditer(code):
        code_window = code[match.start() : match.start() + 1200]
        if owner_pattern.search(code_window):
            return True
    return False


def _js_ts_has_effective_ownership_check(rendered: str, untrusted_helpers: set[str] | None = None) -> bool:
    if not _js_ts_has_effective_auth_guard(rendered, untrusted_helpers):
        return False
    return _js_ts_ownership_is_bound_to_data_access(rendered)


def _js_ts_local_untrusted_auth_helpers(text: str) -> set[str]:
    untrusted: set[str] = set()
    pattern = re.compile(
        r"(?:async\s+)?function\s+(requireauth|require_auth|verifytoken|verifyidtoken|auth)\s*\([^)]*\)\s*\{",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(text):
        body = _extract_braced_body(text, match.end() - 1).casefold()
        if not _js_ts_helper_enforces_auth(body):
            untrusted.add(match.group(1).casefold())
    arrow_pattern = re.compile(
        r"\b(?:const|let)\s+(requireauth|require_auth|verifytoken|verifyidtoken|auth)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in arrow_pattern.finditer(text):
        tail = text[match.end() :]
        if tail.lstrip().startswith("{"):
            open_brace = match.end() + len(tail) - len(tail.lstrip())
            body = _extract_braced_body(text, open_brace).casefold()
        else:
            body = re.split(r"[;\n]", tail, maxsplit=1)[0].casefold()
        if not _js_ts_helper_enforces_auth(body):
            untrusted.add(match.group(1).casefold())
    return untrusted


def _js_ts_has_ownership_check(rendered: str) -> bool:
    if not _js_ts_has_auth_guard(rendered):
        return False
    return _js_ts_ownership_is_bound_to_data_access(rendered)


def _js_ts_has_express_id_route(rendered: str) -> bool:
    return bool(re.search(r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['\"][^'\"]*:[a-z0-9_]*id\b", rendered))


def _js_ts_reads_param_id(rendered: str) -> bool:
    return any(term in rendered for term in ("req.params.id", "request.params.id", "params.id", ".findbyid(", ".findunique(", ".doc(")) or bool(
        re.search(r"\b(?:req|request)\.params\.[a-z0-9_]*id\b|\bparams\.[a-z0-9_]*id\b", rendered)
    )


def _js_ts_mentions_rls(rendered: str) -> bool:
    rendered = _js_ts_code_without_strings(rendered)
    return bool(
        re.search(r"\bauth\.uid\s*\(", rendered)
        or re.search(r"\brls[_-]?enabled\s*[:=]\s*true\b", rendered)
        or re.search(r"\browlevelsecurity\s*[:=]\s*true\b", rendered)
        or re.search(r"\bcreatepolicy\s*\(", rendered)
    )


@lru_cache(maxsize=4096)
def _js_ts_code_without_strings(rendered: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for char in rendered:
        if escaped:
            output.append(" " if quote else char)
            escaped = False
        elif char == "\\":
            output.append(" " if quote else char)
            escaped = True
        elif quote:
            output.append("\n" if char == "\n" else " ")
            if char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            output.append(" ")
            quote = char
        else:
            output.append(char)
    return "".join(output)


def _js_ts_has_request_id_access(rendered: str) -> bool:
    return any(term in rendered for term in ("req.params.id", "params.id", "request.nexturl", "searchparams", ".doc(")) or bool(
        re.search(r"\b(?:req|request)\.params\.[a-z0-9_]*id\b|\bparams\.[a-z0-9_]*id\b", rendered)
    )


def _js_ts_has_firebase_admin_access(rendered: str) -> bool:
    lowered = rendered.casefold()
    return (
        _js_ts_has_request_id_access(lowered)
        or bool(re.search(r"\.(?:collection|doc)\s*\(", lowered))
        and bool(re.search(r"\.(?:get|set|add|update|delete|create)\s*\(", lowered))
    )


def _js_ts_expand_scope_with_local_callees(scope: JsTsHandlerScope, text: str) -> JsTsHandlerScope:
    executable = _js_ts_code_without_strings(scope.rendered)
    ignored = {
        "catch",
        "console",
        "delete",
        "do",
        "for",
        "if",
        "json",
        "map",
        "reduce",
        "response",
        "switch",
        "while",
    }
    helpers: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"(?<![.$A-Za-z0-9_])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", executable):
        name = match.group(1)
        if name.casefold() in ignored or name.casefold() in seen:
            continue
        seen.add(name.casefold())
        helper = _js_ts_named_function_scope(text, name)
        if helper is None or helper.rendered in scope.rendered:
            continue
        helpers.append(helper.rendered)
        if len(helpers) >= 8 or sum(len(item) for item in helpers) >= 16000:
            break
    if not helpers:
        return scope
    return JsTsHandlerScope(scope.kind, "\n".join((scope.rendered, *helpers)), scope.line)


def _js_ts_route_handler_scopes(path: Path, text: str) -> list[JsTsHandlerScope]:
    scopes: list[JsTsHandlerScope] = []
    seen_braces: set[int] = set()
    next_patterns = (
        re.compile(
            r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\([^)]*\)\s*(?::[^{};]+)?\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
        re.compile(
            r"\bexport\s+(?:const|let)\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*(?::[^=;]+)?=\s*(?:async\s*)?\([^)]*\)\s*(?::[^={};]+)?\s*=>\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
    )
    for pattern in next_patterns:
        for match in pattern.finditer(text):
            open_brace = match.end() - 1
            if open_brace in seen_braces:
                continue
            seen_braces.add(open_brace)
            scopes.append(
                JsTsHandlerScope(
                    "next_route",
                    text[match.start() : open_brace] + _extract_braced_body(text, open_brace),
                    text[: match.start()].count("\n") + 1,
                )
            )

    express_route = re.compile(
        r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*(['\"])[^'\"]*:[a-z0-9_]*id\b[^'\"]*\1\s*,",
        re.IGNORECASE | re.MULTILINE,
    )
    callback = re.compile(
        r"(?:\basync\s+)?(?:function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\)|\([^)]*\)\s*(?::[^={};]+)?\s*=>)\s*\{",
        re.IGNORECASE | re.MULTILINE,
    )
    for route_match in express_route.finditer(text):
        search_end = min(len(text), route_match.end() + 8000)
        named = re.match(r"\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)", text[route_match.end() : search_end])
        if named is not None:
            named_scope = _js_ts_named_function_scope(text, named.group(1))
            if named_scope is not None:
                scopes.append(
                    JsTsHandlerScope(
                        "express_route",
                        text[route_match.start() : route_match.end()] + named_scope.rendered,
                        text[: route_match.start()].count("\n") + 1,
                    )
                )
                continue
        callback_match = callback.search(text, route_match.end(), search_end)
        if callback_match is None:
            continue
        open_brace = callback_match.end() - 1
        if open_brace in seen_braces:
            continue
        seen_braces.add(open_brace)
        scopes.append(
            JsTsHandlerScope(
                "express_route",
                text[route_match.start() : open_brace] + _extract_braced_body(text, open_brace),
                text[: route_match.start()].count("\n") + 1,
            )
        )
    return sorted(scopes, key=lambda scope: (scope.line, scope.kind))


def _js_ts_express_routes(text: str) -> list[JsTsExpressRoute]:
    route_pattern = re.compile(
        r"\b(?:app|router)\.(?P<method>get|post|put|patch|delete)\s*\(\s*"
        r"(?P<quote>['\"])(?P<path>[^'\"]+)(?P=quote)\s*,",
        re.IGNORECASE | re.MULTILINE,
    )
    callback_pattern = re.compile(
        r"(?:\basync\s+)?(?:"
        r"function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\((?P<function_params>[^)]*)\)"
        r"|\((?P<arrow_params>[^)]*)\)\s*(?::[^={};]+)?\s*=>"
        r")\s*\{",
        re.IGNORECASE | re.MULTILINE,
    )
    routes: list[JsTsExpressRoute] = []
    for route_match in route_pattern.finditer(text):
        search_end = min(len(text), route_match.end() + 8000)
        callback_match = callback_pattern.search(text, route_match.end(), search_end)
        if callback_match is None:
            continue
        params = _js_ts_param_names(
            callback_match.group("function_params")
            or callback_match.group("arrow_params")
            or ""
        )
        lowered_params = {param.casefold() for param in params}
        if not lowered_params.intersection({"req", "request"}) or not lowered_params.intersection(
            {"res", "response"}
        ):
            continue
        raw_middleware = text[route_match.end() : callback_match.start()].strip().strip(",")
        middleware = tuple(
            re.sub(r"\s+", "", part).casefold()
            for part in _js_ts_split_top_level(raw_middleware)
            if part.strip()
        )
        open_brace = callback_match.end() - 1
        routes.append(
            JsTsExpressRoute(
                method=route_match.group("method").casefold(),
                path=route_match.group("path"),
                middleware=middleware,
                body=_extract_braced_body(text, open_brace),
                line=text[: route_match.start()].count("\n") + 1,
            )
        )
    return routes


def _js_ts_mongo_raw_response(body: str, operation: str) -> tuple[str, str] | None:
    rendered = "\n".join(_strip_js_ts_comments(body.splitlines()))
    collection_pattern = re.compile(
        rf"\.collection\s*\(\s*(['\"])(?P<collection>[^'\"]+)\1\s*\)"
        rf"[\s\S]{{0,240}}?\.{re.escape(operation)}\s*\(",
        re.IGNORECASE,
    )
    for collection_match in collection_pattern.finditer(rendered):
        tail = rendered[collection_match.end() : collection_match.end() + 2400]
        if operation == "find":
            query_end = re.match(r"\s*(?:\{\s*\})?\s*\)", tail)
            if query_end is None:
                continue
            result_tail = tail[query_end.end() :]
            callback = re.search(
                r"\.toArray\s*\(\s*(?:async\s*)?(?:function\s*)?\(\s*"
                r"[A-Za-z_$][A-Za-z0-9_$]*\s*,\s*(?P<result>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)",
                result_tail,
                re.IGNORECASE,
            )
        else:
            callback = re.search(
                r",\s*(?:async\s*)?(?:function\s*)?\(\s*"
                r"[A-Za-z_$][A-Za-z0-9_$]*\s*,\s*(?P<result>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)",
                tail,
                re.IGNORECASE,
            )
        if callback is None:
            continue
        result_name = callback.group("result")
        response_tail = tail[callback.end() :]
        if not re.search(
            rf"\b(?:res|response)\.(?:send|json)\s*\(\s*{re.escape(result_name)}\s*\)",
            response_tail,
            re.IGNORECASE,
        ):
            continue
        return collection_match.group("collection").casefold(), result_name.casefold()
    return None


def _js_ts_express_detail_has_equivalent_collection_peer(
    text: str,
    scope: JsTsHandlerScope,
) -> bool:
    routes = _js_ts_express_routes(text)
    detail = next((route for route in routes if route.line == scope.line), None)
    if detail is None or detail.method != "get":
        return False
    detail_read = _js_ts_mongo_raw_response(detail.body, "findOne")
    if detail_read is None:
        return False
    collection, _ = detail_read
    for candidate in routes:
        if candidate.line == detail.line or candidate.method != "get":
            continue
        if candidate.middleware != detail.middleware:
            continue
        list_read = _js_ts_mongo_raw_response(candidate.body, "find")
        if list_read is not None and list_read[0] == collection:
            return True
    return False


def _js_ts_named_function_scope(text: str, name: str) -> JsTsHandlerScope | None:
    escaped = re.escape(name)
    patterns = (
        re.compile(rf"\b(?:async\s+)?function\s+{escaped}\s*\([^)]*\)\s*(?::[^{{}};]+)?\s*\{{", re.IGNORECASE | re.MULTILINE),
        re.compile(
            rf"\b(?:const|let)\s+{escaped}\s*(?::[^=;]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^={{}};]+)?=>\s*\{{",
            re.IGNORECASE | re.MULTILINE,
        ),
    )
    for pattern in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        open_brace = match.end() - 1
        return JsTsHandlerScope(
            "named_function",
            text[match.start() : open_brace] + _extract_braced_body(text, open_brace),
            text[: match.start()].count("\n") + 1,
        )
    return None


def _js_ts_parenthesized_content(text: str, open_paren: int) -> str:
    if open_paren < 0 or open_paren >= len(text) or text[open_paren] != "(":
        return ""
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
    return text[open_paren + 1 :]


def _js_ts_request_derived_names(text: str) -> set[str]:
    statements = _js_ts_logical_statements(_strip_js_ts_comments(text.splitlines()))
    derived: set[str] = set()
    for _, _, rendered in statements:
        for param in _js_ts_request_params(rendered):
            derived.add(param)
    if re.search(r"\bparams\.[A-Za-z_$]", text):
        derived.add("params")
    for _ in range(4):
        changed = False
        for _, _, rendered in statements:
            assignment = _js_ts_assignment(rendered)
            if assignment is None:
                continue
            targets, expression = assignment
            executable = _js_ts_code_without_literals(expression)
            direct = _js_ts_source_kind(executable) == "request_body"
            inherited = any(re.search(rf"\b{re.escape(name)}\b", executable) for name in derived)
            if not direct and not inherited:
                continue
            for target in targets:
                if target not in derived:
                    derived.add(target)
                    changed = True
        if not changed:
            break
    return derived


def _js_ts_logical_statements(lines: list[str] | tuple[str, ...]) -> list[tuple[int, int, str]]:
    return list(_js_ts_logical_statements_cached(tuple(lines)))


@lru_cache(maxsize=1024)
def _js_ts_logical_statements_cached(lines: tuple[str, ...]) -> tuple[tuple[int, int, str], ...]:
    statements: list[tuple[int, int, str]] = []
    buffer: list[str] = []
    start = 1
    paren_depth = 0
    bracket_depth = 0
    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not buffer and not stripped:
            continue
        if not buffer:
            start = line_no
        buffer.append(raw_line)
        code = _js_ts_code_without_literals(raw_line)
        paren_depth += code.count("(") - code.count(")")
        bracket_depth += code.count("[") - code.count("]")
        complete = paren_depth <= 0 and bracket_depth <= 0 and (
            ";" in code or stripped.endswith(("}", "});", ")"))
        )
        if not complete:
            continue
        rendered = " ".join(part.strip() for part in buffer if part.strip())
        statements.append((start, line_no, rendered))
        buffer = []
        paren_depth = 0
        bracket_depth = 0
    if buffer:
        statements.append((start, len(lines), " ".join(part.strip() for part in buffer if part.strip())))
    return tuple(statements)


def _js_ts_statement_taint_lookup(
    taints: dict[int, dict[str, tuple[TaintSource, bool]]],
    bindings: dict[int, set[str]],
    parents: dict[int, int | None],
    scope_id: int,
    name: str,
) -> tuple[TaintSource, bool] | None:
    current: int | None = scope_id
    while current is not None:
        if name in bindings.get(current, set()):
            return taints.get(current, {}).get(name)
        if name in taints.get(current, {}):
            return taints[current][name]
        current = parents.get(current)
    return None


def _js_ts_exported_function_scopes(text: str) -> list[JsTsHandlerScope]:
    scopes: list[JsTsHandlerScope] = []
    seen_braces: set[int] = set()
    patterns = (
        re.compile(
            r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)\s*(?::[^{};]+)?\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
        re.compile(
            r"\bexport\s+(?:const|let)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^={};]+)?\s*=>\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            open_brace = match.end() - 1
            if open_brace in seen_braces:
                continue
            seen_braces.add(open_brace)
            scopes.append(
                JsTsHandlerScope(
                    "exported_function",
                    text[match.start() : open_brace] + _extract_braced_body(text, open_brace),
                    text[: match.start()].count("\n") + 1,
                )
            )
    return sorted(scopes, key=lambda scope: scope.line)


def _js_ts_scope_first_line(scope: JsTsHandlerScope, needles: tuple[str, ...]) -> int:
    relative = _first_line_matching(scope.rendered.splitlines(), needles)
    return scope.line + relative - 1


def _collect_js_ts_function_summaries(path: Path, lines: list[str]) -> list[JsTsFunctionSummary]:
    text = "\n".join(lines)
    lower_text = text.lower()
    if not any(
        marker in lower_text
        for marker in (
            ".findunique(",
            ".findfirst(",
            ".findbyid(",
            ".from(",
            ".select(",
            ".doc(",
            ".collection(",
            ".query(",
            ".execute(",
            "select ",
        )
    ):
        return []
    summaries: list[JsTsFunctionSummary] = []
    patterns = (
        re.compile(r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*{", re.MULTILINE),
        re.compile(r"(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*{", re.MULTILINE),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            params = tuple(_js_ts_param_names(match.group(2)))
            if not params:
                continue
            open_brace = text.find("{", match.end() - 1)
            if open_brace < 0:
                continue
            body = _extract_braced_body(text, open_brace)
            lower = body.lower()
            data_access = _js_ts_data_access_kind(lower)
            if not data_access:
                continue
            if not _js_ts_body_uses_param_identifier(lower, params):
                continue
            if _js_ts_has_service_scope_constraint(lower):
                continue
            line = text[: match.start()].count("\n") + 1
            summaries.append(
                JsTsFunctionSummary(
                    name=name,
                    file=str(path),
                    line=line,
                    line_hash=_line_hash(lines, line),
                    risk="request_id_to_unscoped_data_read",
                    data_access=data_access,
                    param_names=tuple(_safe_label(param) for param in params),
                )
            )
    return summaries


def _js_ts_param_names(raw: str) -> list[str]:
    names: list[str] = []
    for part in str(raw or "").split(","):
        candidate = part.split(":", 1)[0].strip().strip("{}[]")
        if JS_TS_IDENT.fullmatch(candidate):
            names.append(candidate)
    return names


def _extract_braced_body(text: str, open_brace: int, max_chars: int = 8000) -> str:
    depth = 0
    quote: str | None = None
    escaped = False
    end = min(len(text), open_brace + max_chars)
    for index in range(open_brace, end):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace : index + 1]
    return text[open_brace:end]


def _js_ts_data_access_kind(rendered: str) -> str:
    for label, needles in (
        ("prisma_find_unique", (".findunique(", ".findfirst(", ".findbyid(")),
        ("supabase_table_read", (".from(", ".select(")),
        ("firebase_doc_read", (".doc(", ".collection(")),
        ("sql_query", (".query(", ".execute(", "select ")),
    ):
        if any(needle in rendered for needle in needles):
            return label
    return ""


def _js_ts_body_uses_param_identifier(rendered: str, params: tuple[str, ...]) -> bool:
    id_like = {"id", "userid", "user_id", "orderid", "order_id", "profileid", "profile_id", "tenantid", "tenant_id"}
    for param in params:
        lowered = param.lower()
        if lowered in id_like and re.search(rf"\b{re.escape(param)}\b", rendered, re.IGNORECASE):
            return True
        if lowered.endswith("id") and re.search(rf"\b{re.escape(param)}\b", rendered, re.IGNORECASE):
            return True
    return False


def _js_ts_has_service_scope_constraint(rendered: str) -> bool:
    return any(
        term in rendered
        for term in (
            "ownerid",
            "owner_id",
            "tenantid",
            "tenant_id",
            "teamid",
            "team_id",
            "organizationid",
            "orgid",
            "auth.uid",
            "session.user",
            "currentuser",
            "actor.userid",
            "actor.user_id",
        )
    )


def _first_line_matching(lines: list[str], needles: tuple[str, ...]) -> int:
    for index, line in enumerate(lines, start=1):
        lower = line.lower()
        if any(needle in lower for needle in needles):
            return index
    return 1


def _line_hash(lines: list[str], line: int, cache: dict[str, str] | None = None) -> str:
    value = lines[line - 1] if 1 <= line <= len(lines) else ""
    if cache is None:
        return evidence_hash(value)
    cached = cache.get(value)
    if cached is None:
        cached = evidence_hash(value)
        cache[value] = cached
    return cached


def _safe_label(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > 48:
        value = value[:47] + "..."
    return value or "source"
