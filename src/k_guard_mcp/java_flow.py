from __future__ import annotations

import copy
import operator
from dataclasses import dataclass, field
from typing import Any, Iterable

from tree_sitter import Language, Node, Parser
import tree_sitter_java


class _UnknownValue:
    def __deepcopy__(self, memo: dict[int, Any]) -> "_UnknownValue":
        return self


_UNKNOWN = _UnknownValue()
_HTTP_SOURCE_METHODS = {
    "getCookies",
    "getHeader",
    "getHeaders",
    "getInputStream",
    "getParameter",
    "getParameterMap",
    "getParameterNames",
    "getParameterValues",
    "getPathInfo",
    "getQueryString",
    "getReader",
}
_SQL_SINK_METHODS = {
    "addBatch",
    "batchUpdate",
    "execute",
    "executeBatch",
    "executeLargeBatch",
    "executeLargeUpdate",
    "executeQuery",
    "executeUpdate",
    "prepareCall",
    "prepareStatement",
    "query",
    "queryForList",
    "queryForMap",
    "queryForObject",
    "queryForRowSet",
    "update",
}
_SQL_OBJECT_MARKERS = (
    "callablestatement",
    "connection",
    "entitymanager",
    "jdbctemplate",
    "namedparameterjdbctemplate",
    "preparedstatement",
    "statement",
)
_NUMERIC_SANITIZERS = {
    "byteValue",
    "doubleValue",
    "floatValue",
    "intValue",
    "longValue",
    "parseDouble",
    "parseFloat",
    "parseInt",
    "parseLong",
    "shortValue",
}
_BOOLEAN_METHODS = {
    "contains",
    "containsKey",
    "containsValue",
    "endsWith",
    "equals",
    "equalsIgnoreCase",
    "hasMoreElements",
    "isBlank",
    "isEmpty",
    "isPresent",
    "matches",
    "startsWith",
}


@dataclass(frozen=True)
class JavaSqlFlow:
    line: int
    subtype: str


class JavaFlowParseError(ValueError):
    """Raised when the Java AST is incomplete and a bounded fallback is required."""


@dataclass
class _Value:
    tainted: bool = False
    const: Any = _UNKNOWN
    kind: str = ""
    sequence: list["_Value"] | None = None
    mapping: dict[Any, "_Value"] | None = None

    @classmethod
    def clean(cls, const: Any = _UNKNOWN, *, kind: str = "") -> "_Value":
        return cls(False, const, kind)

    @classmethod
    def dirty(cls, *, kind: str = "") -> "_Value":
        return cls(True, _UNKNOWN, kind)


@dataclass
class _State:
    values: dict[str, _Value] = field(default_factory=dict)
    returns: list[_Value] = field(default_factory=list)

    def clone(self) -> "_State":
        return copy.deepcopy(self)


def scan_java_sql_flows(text: str, *, entrypoint_names: set[str] | None = None) -> list[JavaSqlFlow]:
    """Track servlet/Spring input into Java SQL APIs with a bounded AST pass.

    The pass is intentionally local to one source file. It evaluates literal arithmetic
    branches, follows common collection/string propagators, and executes same-file
    helper summaries. Unknown branches are joined conservatively.
    """

    source = text.encode("utf-8", errors="replace")
    parser = Parser(Language(tree_sitter_java.language()))
    tree = parser.parse(source)
    if tree.root_node.has_error:
        raise JavaFlowParseError("Java source contains an incomplete syntax tree")
    analyzer = _JavaFlowAnalyzer(source, tree.root_node)
    return analyzer.run(entrypoint_names=entrypoint_names)


class _JavaFlowAnalyzer:
    def __init__(self, source: bytes, root: Node) -> None:
        self.source = source
        self.root = root
        self.methods: dict[str, list[Node]] = {}
        self.class_names: set[str] = set()
        self.findings: set[tuple[int, str]] = set()
        self._call_stack: list[tuple[str, tuple[bool, ...]]] = []
        for node in _walk(root):
            if node.type in {"class_declaration", "record_declaration", "enum_declaration"}:
                class_name = self._field_text(node, "name")
                if class_name:
                    self.class_names.add(class_name)
            if node.type != "method_declaration":
                continue
            name = self._field_text(node, "name")
            if name:
                self.methods.setdefault(name, []).append(node)

    def run(self, *, entrypoint_names: set[str] | None = None) -> list[JavaSqlFlow]:
        entries: list[Node] = []
        method_groups = self.methods.items()
        for name, methods in method_groups:
            for method in methods:
                if (entrypoint_names is not None and name in entrypoint_names) or (
                    entrypoint_names is None and self._is_entrypoint(method)
                ):
                    entries.append(method)
        for method in entries:
            self._invoke_method(method, None, depth=0)
        return [JavaSqlFlow(line, subtype) for line, subtype in sorted(self.findings)]

    def _is_entrypoint(self, method: Node) -> bool:
        name = self._field_text(method, "name")
        params = method.child_by_field_name("parameters")
        signature = self._text(method)[: max(0, (params.end_byte - method.start_byte) if params else 500)]
        if "HttpServletRequest" in signature:
            return True
        if any(marker in signature for marker in ("@RequestParam", "@PathVariable", "@RequestHeader", "@CookieValue")):
            return True
        prefix = self.source[max(0, method.start_byte - 500) : method.start_byte].decode("utf-8", errors="replace")
        return name in {"doGet", "doPost", "service"} or any(
            marker in prefix for marker in ("@GetMapping", "@PostMapping", "@PutMapping", "@PatchMapping", "@DeleteMapping", "@RequestMapping")
        )

    def _invoke_method(self, method: Node, args: list[_Value] | None, *, depth: int) -> _Value:
        if depth > 5:
            return _join_values(args or [])
        name = self._field_text(method, "name")
        params_node = method.child_by_field_name("parameters")
        params = [child for child in (params_node.named_children if params_node else []) if child.type in {"formal_parameter", "spread_parameter"}]
        state = _State()
        arg_values = list(args or [])
        signature_key: list[bool] = []
        for index, param in enumerate(params):
            param_name = self._field_text(param, "name")
            param_type = self._field_text(param, "type")
            value = copy.deepcopy(arg_values[index]) if index < len(arg_values) else _Value.clean()
            if "HttpServletRequest" in param_type:
                value.kind = "http_request"
            elif any(annotation in self._text(param) for annotation in ("@RequestParam", "@PathVariable", "@RequestHeader", "@CookieValue")):
                value = _Value.dirty(kind="http_value")
            state.values[param_name] = value
            signature_key.append(value.tainted)
        call_key = (name, tuple(signature_key))
        if call_key in self._call_stack:
            return _join_values(arg_values)
        body = method.child_by_field_name("body")
        if body is None:
            return _join_values(arg_values)
        self._call_stack.append(call_key)
        try:
            self._exec(body, state, depth=depth)
        finally:
            self._call_stack.pop()
        return _join_values(state.returns) if state.returns else _Value.clean()

    def _exec(self, node: Node, state: _State, *, depth: int) -> None:
        kind = node.type
        if kind in {"block", "constructor_body"}:
            for child in node.named_children:
                self._exec(child, state, depth=depth)
            return
        if kind in {"local_variable_declaration", "field_declaration"}:
            declared_type = self._field_text(node, "type")
            for declarator in (child for child in node.named_children if child.type == "variable_declarator"):
                name = self._field_text(declarator, "name")
                value_node = declarator.child_by_field_name("value")
                value = self._eval(value_node, state, depth=depth) if value_node else _Value.clean()
                if declared_type and not value.kind:
                    value.kind = declared_type
                state.values[name] = value
            return
        if kind == "expression_statement":
            if node.named_children:
                self._eval(node.named_children[0], state, depth=depth)
            return
        if kind == "if_statement":
            condition = self._eval(node.child_by_field_name("condition"), state, depth=depth)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if condition.const is True:
                if consequence:
                    self._exec(consequence, state, depth=depth)
                return
            if condition.const is False:
                if alternative:
                    self._exec(alternative, state, depth=depth)
                return
            left = state.clone()
            right = state.clone()
            if consequence:
                self._exec(consequence, left, depth=depth)
            if alternative:
                self._exec(alternative, right, depth=depth)
            self._join_states(state, left, right)
            return
        if kind == "enhanced_for_statement":
            collection = self._eval(node.child_by_field_name("value"), state, depth=depth)
            item_name = self._field_text(node, "name")
            loop_state = state.clone()
            loop_state.values[item_name] = _collection_value(collection)
            body = node.child_by_field_name("body")
            if body:
                self._exec(body, loop_state, depth=depth)
            self._join_states(state, state.clone(), loop_state)
            return
        if kind in {"for_statement", "while_statement", "do_statement"}:
            loop_state = state.clone()
            body = node.child_by_field_name("body")
            if body:
                self._exec(body, loop_state, depth=depth)
                self._exec(body, loop_state, depth=depth)
            self._join_states(state, state.clone(), loop_state)
            return
        if kind == "return_statement":
            expression = next(iter(node.named_children), None)
            state.returns.append(self._eval(expression, state, depth=depth) if expression else _Value.clean())
            return
        if kind in {"try_statement", "catch_clause", "finally_clause", "synchronized_statement", "labeled_statement"}:
            for child in node.named_children:
                if child.type in {"block", "resource_specification", "catch_clause", "finally_clause"}:
                    self._exec(child, state, depth=depth)
            return
        if kind in {"switch_expression", "switch_statement"}:
            self._exec_switch(node, state, depth=depth)
            return
        if kind in {"switch_block", "switch_block_statement_group", "switch_rule"}:
            for child in node.named_children:
                self._exec(child, state, depth=depth)
            return
        for child in node.named_children:
            if child.type.endswith("statement") or child.type in {"block", "local_variable_declaration"}:
                self._exec(child, state, depth=depth)

    def _eval(self, node: Node | None, state: _State, *, depth: int) -> _Value:
        if node is None:
            return _Value.clean()
        kind = node.type
        if kind == "identifier":
            return copy.deepcopy(state.values.get(self._text(node), _Value.clean()))
        if kind in {"string_literal", "character_literal"}:
            raw = self._text(node)
            return _Value.clean(raw[1:-1] if len(raw) >= 2 else "")
        if kind in {"decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal"}:
            raw = self._text(node).rstrip("lL").replace("_", "")
            try:
                return _Value.clean(int(raw, 0))
            except ValueError:
                return _Value.clean()
        if kind in {"decimal_floating_point_literal", "hex_floating_point_literal"}:
            try:
                return _Value.clean(float(self._text(node).rstrip("fFdD").replace("_", "")))
            except ValueError:
                return _Value.clean()
        if kind in {"true", "false"}:
            return _Value.clean(kind == "true")
        if kind == "null_literal":
            return _Value.clean(None)
        if kind in {"parenthesized_expression", "cast_expression"}:
            candidate = node.child_by_field_name("value") or next(
                (child for child in reversed(node.named_children) if child.type not in {"type_identifier", "integral_type", "generic_type"}),
                None,
            )
            return self._eval(candidate, state, depth=depth)
        if kind == "assignment_expression":
            right = self._eval(node.child_by_field_name("right"), state, depth=depth)
            left = node.child_by_field_name("left")
            if left is not None:
                self._assign(left, right, state)
            return copy.deepcopy(right)
        if kind == "binary_expression":
            return self._eval_binary(node, state, depth=depth)
        if kind == "unary_expression":
            value = self._eval(node.child_by_field_name("operand"), state, depth=depth)
            operator_text = self._field_text(node, "operator")
            if value.const is not _UNKNOWN:
                try:
                    if operator_text == "!":
                        return _Value.clean(not value.const)
                    if operator_text == "-":
                        return _Value.clean(-value.const)
                    if operator_text == "+":
                        return _Value.clean(+value.const)
                except (TypeError, ValueError):
                    pass
            return _Value(value.tainted)
        if kind == "ternary_expression":
            condition = self._eval(node.child_by_field_name("condition"), state, depth=depth)
            if condition.const is True:
                return self._eval(node.child_by_field_name("consequence"), state, depth=depth)
            if condition.const is False:
                return self._eval(node.child_by_field_name("alternative"), state, depth=depth)
            return _join_values(
                [
                    self._eval(node.child_by_field_name("consequence"), state, depth=depth),
                    self._eval(node.child_by_field_name("alternative"), state, depth=depth),
                ]
            )
        if kind == "array_access":
            array_value = self._eval(node.child_by_field_name("array"), state, depth=depth)
            index_value = self._eval(node.child_by_field_name("index"), state, depth=depth)
            return _indexed_value(array_value, index_value.const)
        if kind in {"array_initializer", "element_value_array_initializer"}:
            values = [self._eval(child, state, depth=depth) for child in node.named_children]
            return _Value(any(value.tainted for value in values), sequence=values, kind="array")
        if kind == "object_creation_expression":
            return self._eval_object_creation(node, state, depth=depth)
        if kind == "method_invocation":
            return self._eval_method(node, state, depth=depth)
        if kind == "field_access":
            text = self._text(node)
            if text.endswith(".length"):
                object_node = node.child_by_field_name("object")
                value = self._eval(object_node, state, depth=depth)
                if value.sequence is not None:
                    return _Value.clean(len(value.sequence))
                return _Value.clean()
            return copy.deepcopy(state.values.get(text, _Value.clean()))
        if kind == "this":
            return _Value.clean(kind="this")
        values = [self._eval(child, state, depth=depth) for child in node.named_children]
        return _join_values(values)

    def _eval_binary(self, node: Node, state: _State, *, depth: int) -> _Value:
        left = self._eval(node.child_by_field_name("left"), state, depth=depth)
        right = self._eval(node.child_by_field_name("right"), state, depth=depth)
        op = self._field_text(node, "operator")
        operations = {
            "+": operator.add,
            "-": operator.sub,
            "*": operator.mul,
            "/": operator.truediv,
            "%": operator.mod,
            ">": operator.gt,
            ">=": operator.ge,
            "<": operator.lt,
            "<=": operator.le,
            "==": operator.eq,
            "!=": operator.ne,
            "&&": lambda a, b: bool(a and b),
            "||": lambda a, b: bool(a or b),
        }
        if left.const is not _UNKNOWN and right.const is not _UNKNOWN and op in operations:
            try:
                return _Value(left.tainted or right.tainted, operations[op](left.const, right.const))
            except (TypeError, ValueError, ZeroDivisionError):
                pass
        return _Value(left.tainted or right.tainted)

    def _eval_object_creation(self, node: Node, state: _State, *, depth: int) -> _Value:
        type_text = self._field_text(node, "type")
        args = self._argument_values(node, state, depth=depth)
        lower = type_text.casefold()
        if any(marker in lower for marker in ("arraylist", "linkedlist", "vector")):
            return _Value(False, kind=type_text, sequence=[])
        if any(marker in lower for marker in ("hashmap", "treemap", "linkedhashmap")):
            return _Value(False, kind=type_text, mapping={})
        if "stringbuilder" in lower or "stringbuffer" in lower:
            return _Value(any(value.tainted for value in args), kind=type_text)
        if any(value.kind == "http_request" for value in args):
            return _Value.clean(kind="request_wrapper")
        return _Value(any(value.tainted for value in args), kind=type_text)

    def _eval_method(self, node: Node, state: _State, *, depth: int) -> _Value:
        name = self._field_text(node, "name")
        object_node = node.child_by_field_name("object")
        object_text = self._text(object_node) if object_node else ""
        object_value = self._eval(object_node, state, depth=depth) if object_node else _Value.clean()
        args = self._argument_values(node, state, depth=depth)

        if name in _HTTP_SOURCE_METHODS and object_value.kind == "http_request":
            return _Value.dirty(kind="http_value")
        if object_value.kind == "request_wrapper" and _looks_like_wrapper_source(name):
            return _Value.dirty(kind="http_value")
        if name in _NUMERIC_SANITIZERS:
            return _Value.clean(kind="number")
        if name == "encodeForSQL":
            return _Value.clean(kind="sql_encoded")
        if name in _BOOLEAN_METHODS:
            return _Value.clean(kind="boolean")
        if name in {"length", "size", "hashCode", "indexOf", "lastIndexOf"}:
            if object_value.sequence is not None and name == "size":
                return _Value.clean(len(object_value.sequence), kind="number")
            return _Value.clean(kind="number")
        if name == "charAt" and isinstance(object_value.const, str) and args and isinstance(args[0].const, int):
            index = args[0].const
            if -len(object_value.const) <= index < len(object_value.const):
                return _Value(object_value.tainted, object_value.const[index], kind="char")

        if name in {"add", "append", "addFirst", "addLast", "offer", "push"} and object_text in state.values:
            target = state.values[object_text]
            added = copy.deepcopy(args[-1] if args else _Value.clean())
            if target.sequence is not None:
                target.sequence.append(added)
            target.tainted = target.tainted or added.tainted
            return copy.deepcopy(target)
        if name == "put" and object_text in state.values:
            target = state.values[object_text]
            key = args[0].const if args and args[0].const is not _UNKNOWN else _UNKNOWN
            added = copy.deepcopy(args[1] if len(args) > 1 else _Value.clean())
            if target.mapping is not None:
                target.mapping[key] = added
            target.tainted = target.tainted or added.tainted
            return copy.deepcopy(added)
        if name in {"remove", "poll", "pop"} and object_text in state.values:
            target = state.values[object_text]
            key = args[0].const if args and args[0].const is not _UNKNOWN else 0
            return _remove_value(target, key)
        if name in {"get", "elementAt", "peek", "firstElement", "lastElement", "nextElement"}:
            key = args[0].const if args and args[0].const is not _UNKNOWN else _UNKNOWN
            return _indexed_value(object_value, key)

        if name in _SQL_SINK_METHODS and self._is_sql_invocation(name, object_text, object_value):
            sql_value = args[0] if args else object_value
            already_reported = not args and "reported" in object_value.kind.casefold()
            if sql_value.tainted and not already_reported:
                subtype = "java_ast_prepared_sql" if name in {"prepareCall", "prepareStatement"} else "java_ast_request_to_sql"
                self.findings.add((node.start_point.row + 1, subtype))
            if name in {"prepareCall", "prepareStatement", "addBatch"}:
                suffix = ":reported" if sql_value.tainted else ""
                return _Value(sql_value.tainted, kind=f"PreparedStatement{suffix}")

        candidates = self.methods.get(name, [])
        internal_receiver = object_node is None or object_text in {"this", "super"}
        if object_node is not None and object_node.type == "object_creation_expression":
            internal_receiver = self._field_text(object_node, "type").split(".")[-1] in self.class_names
        if candidates and internal_receiver and not object_text.startswith(("request", "response")):
            method = min(candidates, key=lambda candidate: abs(len(self._parameters(candidate)) - len(args)))
            return self._invoke_method(method, args, depth=depth + 1)

        if name in {"get", "orElse", "orElseGet"} and object_value.mapping is not None:
            key = args[0].const if args and args[0].const is not _UNKNOWN else _UNKNOWN
            return _indexed_value(object_value, key)
        if name in {"toArray", "split"}:
            return _Value(object_value.tainted or any(value.tainted for value in args), kind="array")
        return _Value(object_value.tainted or any(value.tainted for value in args), kind=object_value.kind)

    def _is_sql_invocation(self, name: str, object_text: str, object_value: _Value) -> bool:
        haystack = f"{object_text} {object_value.kind}".casefold()
        return any(marker in haystack for marker in _SQL_OBJECT_MARKERS) or "databasehelper" in haystack

    def _argument_values(self, node: Node, state: _State, *, depth: int) -> list[_Value]:
        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            return []
        return [self._eval(child, state, depth=depth) for child in args_node.named_children]

    def _exec_switch(self, node: Node, state: _State, *, depth: int) -> None:
        condition = self._eval(node.child_by_field_name("condition"), state, depth=depth)
        body = node.child_by_field_name("body")
        if body is None:
            return
        groups = [child for child in body.named_children if child.type in {"switch_block_statement_group", "switch_rule"}]
        if not groups:
            return
        starts: list[int] = []
        default_index: int | None = None
        for index, group in enumerate(groups):
            label = next((child for child in group.named_children if child.type == "switch_label"), None)
            label_value_node = next(iter(label.named_children), None) if label else None
            if label_value_node is None:
                default_index = index
                continue
            label_value = self._eval(label_value_node, state, depth=depth)
            if condition.const is not _UNKNOWN and label_value.const == condition.const:
                starts = [index]
                break
            if condition.const is _UNKNOWN:
                starts.append(index)
        if not starts and default_index is not None:
            starts = [default_index]
        if not starts:
            return
        branches: list[_State] = []
        for start in starts:
            branch = state.clone()
            for group in groups[start:]:
                for child in group.named_children:
                    if child.type != "switch_label":
                        self._exec(child, branch, depth=depth)
                if any(child.type in {"break_statement", "return_statement", "throw_statement"} for child in group.named_children):
                    break
            branches.append(branch)
        combined = branches[0]
        for branch in branches[1:]:
            joined = state.clone()
            self._join_states(joined, combined, branch)
            combined = joined
        state.values = combined.values
        state.returns.extend(combined.returns)

    def _parameters(self, method: Node) -> list[Node]:
        params = method.child_by_field_name("parameters")
        return list(params.named_children) if params else []

    def _assign(self, left: Node, value: _Value, state: _State) -> None:
        if left.type == "identifier":
            state.values[self._text(left)] = copy.deepcopy(value)
            return
        if left.type == "array_access":
            array_node = left.child_by_field_name("array")
            index_node = left.child_by_field_name("index")
            array_name = self._text(array_node)
            target = state.values.get(array_name)
            index = self._eval(index_node, state, depth=0).const
            if target and target.sequence is not None and isinstance(index, int) and 0 <= index < len(target.sequence):
                target.sequence[index] = copy.deepcopy(value)
                target.tainted = any(item.tainted for item in target.sequence)

    def _join_states(self, target: _State, left: _State, right: _State) -> None:
        names = set(left.values) | set(right.values)
        target.values = {name: _join_value(left.values.get(name), right.values.get(name)) for name in names}
        target.returns = left.returns + right.returns

    def _field_text(self, node: Node, field_name: str) -> str:
        return self._text(node.child_by_field_name(field_name))

    def _text(self, node: Node | None) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node: Node) -> Iterable[Node]:
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _join_values(values: Iterable[_Value]) -> _Value:
    items = list(values)
    if not items:
        return _Value.clean()
    result = copy.deepcopy(items[0])
    for value in items[1:]:
        result = _join_value(result, value)
    return result


def _join_value(left: _Value | None, right: _Value | None) -> _Value:
    if left is None:
        return copy.deepcopy(right or _Value.clean())
    if right is None:
        return copy.deepcopy(left)
    const = left.const if left.const is not _UNKNOWN and left.const == right.const else _UNKNOWN
    kind = left.kind if left.kind == right.kind else left.kind or right.kind
    sequence: list[_Value] | None = None
    if left.sequence is not None and right.sequence is not None and len(left.sequence) == len(right.sequence):
        sequence = [_join_value(a, b) for a, b in zip(left.sequence, right.sequence)]
    mapping: dict[Any, _Value] | None = None
    if left.mapping is not None and right.mapping is not None:
        mapping = {
            key: _join_value(left.mapping.get(key), right.mapping.get(key))
            for key in set(left.mapping) | set(right.mapping)
        }
    return _Value(left.tainted or right.tainted, const, kind, sequence, mapping)


def _collection_value(value: _Value) -> _Value:
    if value.sequence:
        return _join_values(value.sequence)
    if value.mapping:
        return _join_values(value.mapping.values())
    return _Value(value.tainted, kind=value.kind)


def _indexed_value(value: _Value, key: Any) -> _Value:
    if value.sequence is not None:
        if isinstance(key, int) and -len(value.sequence) <= key < len(value.sequence):
            return copy.deepcopy(value.sequence[key])
        return _join_values(value.sequence) if value.sequence else _Value.clean()
    if value.mapping is not None:
        if key in value.mapping:
            return copy.deepcopy(value.mapping[key])
        return _join_values(value.mapping.values()) if value.mapping else _Value.clean()
    return _Value(value.tainted, kind=value.kind)


def _remove_value(value: _Value, key: Any) -> _Value:
    removed = _Value.clean()
    if value.sequence is not None and isinstance(key, int) and -len(value.sequence) <= key < len(value.sequence):
        removed = value.sequence.pop(key)
        value.tainted = any(item.tainted for item in value.sequence)
    elif value.mapping is not None and key in value.mapping:
        removed = value.mapping.pop(key)
        value.tainted = any(item.tainted for item in value.mapping.values())
    return copy.deepcopy(removed)


def _looks_like_wrapper_source(name: str) -> bool:
    lower = name.casefold()
    return lower.startswith(("get", "read", "extract")) and any(
        marker in lower for marker in ("body", "cookie", "header", "input", "parameter", "path", "query", "request")
    )
