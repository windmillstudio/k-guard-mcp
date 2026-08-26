from __future__ import annotations

import ast
import time
from pathlib import Path

import k_guard_mcp.taint as taint_module
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.taint import (
    _call_name,
    _collect_js_ts_function_summaries,
    _collect_python_function_summaries,
    _extract_braced_body,
    _js_ts_assignment,
    _js_ts_body_uses_param_identifier,
    _js_ts_data_access_kind,
    _js_ts_function_scopes,
    _js_ts_has_auth_guard,
    _js_ts_has_data_or_response,
    _js_ts_has_express_id_route,
    _js_ts_has_mutation,
    _js_ts_has_next_route_surface,
    _js_ts_has_ownership_check,
    _js_ts_has_request_id_access,
    _js_ts_has_route_or_action_surface,
    _js_ts_has_server_action,
    _js_ts_mentions_rls,
    _js_ts_request_params,
    _js_ts_rule_id_for_sink,
    _js_ts_sink_kind,
    _js_ts_source_kind,
    _js_ts_target_names,
    _js_ts_title_for_sink,
    _recommendation_for_sink,
    _rule_id_for_sink,
    _severity_for_sink,
    _sink_kind,
    _source_kind,
    _strip_js_ts_comments,
    _target_names,
    _title_for_sink,
    _why_for_sink,
)


def _workspace_rules(tmp_path: Path, files: dict[str, str]) -> set[str]:
    app = tmp_path / "app"
    for relative, text in files.items():
        path = app / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return {finding.rule_id for finding in KGuardScanner().scan_workspace(app).findings}


def test_js_ts_scope_scan_avoids_literal_only_module_backtracking() -> None:
    lines = ["export const bundled = ["]
    lines.extend(
        f'  {{ slug: "icon-{index}", path: "M24 8.77h-2.468v7.565" }},'
        for index in range(2500)
    )
    lines.append("];")

    scope_ids, parents, limited = _js_ts_function_scopes(lines)

    assert set(scope_ids) == {0}
    assert parents == {0: None}
    assert limited is False


def test_js_ts_scope_scan_stays_bounded_for_minified_function_bundle() -> None:
    bundle = ";".join(
        f"function f{index}(value){{return value}};const g{index}=(value)=>{{return value}}"
        for index in range(1200)
    )

    started = time.perf_counter()
    scope_ids, parents, limited = _js_ts_function_scopes([bundle])
    duration = time.perf_counter() - started

    assert scope_ids != (0,)
    assert len(parents) == 2401
    assert limited is False
    assert duration < 5.0


def test_js_ts_scope_marker_budget_fails_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(taint_module, "JS_TS_SCOPE_MARKER_LIMIT", 2)

    rules = _workspace_rules(
        tmp_path,
        {"routes.ts": "const a = () => 1;\nconst b = () => 2;\nconst c = () => 3;\n"},
    )

    assert "STATIC_ANALYSIS_LIMIT_REACHED" in rules


def test_python_security_ast_handles_control_flow_containers_and_all_sinks(tmp_path):
    code = '''
from flask import request, redirect, make_response, render_template_string
import contextlib
import httpx
import os
import subprocess

def helper_constant():
    return "safe"

def helper_request():
    return request.args.get("wrapped")

def no_return():
    pass

async def route(req, cur, response):
    value: str = req.get_query_parameter("value")
    alias = value
    alias += "-suffix"
    pair = (alias, "safe")
    left, right = pair
    items = ["safe", alias]
    items[0] = alias
    items.append(value)
    popped = items.pop(0)
    mapping = {"safe": "x", "danger": value}
    mapping["other"] = popped
    selected = mapping.get("danger", "fallback")
    config = {}
    config.set("section", "key", selected)
    configured = config.get("section", "key")
    named = (captured := configured)
    joined = f"prefix-{named}"
    choice = joined if True else "safe"
    merged = value if req else "safe"
    truthy = (1 + 1 == 2) and (3 != 4) and (4 >= 4) and (3 > 2)
    more = (1 < 2) and (2 <= 2) and (1 in [1, 2]) and (3 not in [1, 2])
    identity = (None is None) and (1 is not None)
    arithmetic = (9 - 2) * 3 / 7 // 1 % 3 ** 1
    negative = -1
    inverted = not False
    unsupported = 1 & 1
    converted = str(int("7"))
    size = len([1, 2])
    failed_conversion = int("not-an-int")
    if truthy and more and identity and inverted:
        sql = "SELECT * FROM users WHERE name='" + choice + "'"
    else:
        sql = "SELECT 1"
    if False:
        os.system("safe")
    else:
        pass
    if req:
        branch_value = selected
    else:
        branch_value = merged
    match "alpha":
        case "alpha" | "beta":
            matched = branch_value
        case _:
            matched = "safe"
    match value:
        case None:
            dynamic_match = "safe"
        case _:
            dynamic_match = matched
    try:
        attempted = dynamic_match
    except ValueError:
        attempted = value
    else:
        attempted += "-else"
    finally:
        finalized = attempted
    for item in [finalized]:
        looped = item
    else:
        looped = finalized
    while False:
        looped = "safe"
    else:
        looped = finalized
    with contextlib.nullcontext(looped) as handled:
        selected = handled
    cur.execute(sql)
    cur.executemany(value)
    os.system(selected)
    subprocess.run(["sh", "-c", selected])
    open(selected)
    redirect(selected)
    httpx.get(selected)
    render_template_string((f"<p>{selected}</p>", 200))
    response.set_cookie("sid", selected, secure=False, httponly=False)
    make_response(f"<p>{selected}</p>")
    return response
'''

    rules = _workspace_rules(tmp_path, {"app.py": code})

    assert {
        "WEB_UNTRUSTED_INPUT_TO_SQL",
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
        "WEB_UNTRUSTED_INPUT_TO_FILE_PATH",
        "API_OPEN_REDIRECT_REQUEST_INPUT",
        "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST",
        "WEB_UNTRUSTED_INPUT_TO_HTML",
        "AUTH_COOKIE_SECURITY_FLAG_DISABLED",
    }.issubset(rules)


def test_python_project_summaries_propagate_request_and_drop_conflicts(tmp_path):
    vulnerable = _workspace_rules(
        tmp_path / "vulnerable",
        {
            "helpers.py": (
                "from flask import request\n"
                "def fixed():\n    return 'safe'\n"
                "def wrapped():\n    return request.args.get('sql')\n"
                "async def async_fixed():\n    return 7\n"
            ),
            "route.py": "def route(cur):\n    sql = wrapped()\n    cur.execute(sql)\n",
        },
    )
    conflict = _workspace_rules(
        tmp_path / "conflict",
        {
            "one.py": "def wrapped():\n    return 'safe'\n",
            "two.py": "from flask import request\ndef wrapped():\n    return request.args.get('sql')\n",
            "route.py": "def route(cur):\n    sql = wrapped()\n    cur.execute(sql)\n",
        },
    )

    assert "WEB_UNTRUSTED_INPUT_TO_SQL" in vulnerable
    assert "WEB_UNTRUSTED_INPUT_TO_SQL" not in conflict
    summaries = _collect_python_function_summaries(ast.parse("def empty():\n    return\ndef many(x):\n    return 1 if x else 2\n"))
    assert summaries == []


def test_taint_helper_contracts_cover_python_and_js_ts_shapes():
    tuple_target = ast.parse("a, obj.value = pair").body[0].targets[0]
    assert _target_names(tuple_target) == ["a", "value"]
    assert _target_names(ast.parse("items[0] = value").body[0].targets[0]) == []

    assert _source_kind(ast.parse("request.args.get('x')", mode="eval").body) == "request_body"
    assert _source_kind(ast.parse("os.getenv('TOKEN')", mode="eval").body) == "env"
    assert _source_kind(ast.parse("cursor.fetchone()", mode="eval").body) == "db_read"
    assert _source_kind(ast.parse("input('x')", mode="eval").body) == "user_input"
    assert _source_kind(ast.parse("42", mode="eval").body) is None

    call_cases = {
        "print(value)": "log",
        "requests.post(value)": "external_http",
        "openai.responses.create(value)": "llm_call",
        "client.call_tool(value)": "mcp_tool_call",
        "jsonify(value)": "response",
        "cursor.execute('UPDATE t SET x=1')": "db_write",
        "model.save(value)": "db_write",
    }
    for source, expected in call_cases.items():
        call = ast.parse(source, mode="eval").body
        assert isinstance(call, ast.Call)
        assert _sink_kind(call) == expected
    select_call = ast.parse("cursor.execute('SELECT 1')", mode="eval").body
    assert isinstance(select_call, ast.Call)
    assert _sink_kind(select_call) is None
    assert _call_name(ast.parse("factory().run()", mode="eval").body) == "factory.run"

    for sink in ("log", "external_http", "llm_call", "mcp_tool_call", "response", "db_write", "unknown"):
        assert _rule_id_for_sink(sink)
        assert _title_for_sink(sink)
        assert _why_for_sink(sink)
        assert _recommendation_for_sink(sink)
        assert _severity_for_sink(sink) in {"high", "medium"}

    stripped = _strip_js_ts_comments(
        [
            "const url = 'https://example.test/a'; // trailing",
            "/* block starts",
            "still block */ const value = `escaped \\` text`;",
            'const quoted = "/* not comment */";',
        ]
    )
    assert "https://example.test/a" in stripped[0]
    assert stripped[1] == ""
    assert "const value" in stripped[2]
    assert "not comment" in stripped[3]

    assert _js_ts_request_params("export async function GET(request: Request, ctx: Ctx) {") == ["request", "ctx"]
    assert _js_ts_request_params("const route = (req, res) => {") == ["req"]
    assert _js_ts_assignment("const {email: alias, phone} = req.body;") == (["alias", "phone"], "req.body")
    assert _js_ts_assignment("profile.email = req.body.email;") == ([], "req.body.email")
    assert _js_ts_assignment("return value") is None
    assert _js_ts_target_names("[first, second]") == ["first", "second"]

    assert _js_ts_source_kind("req.body.email") == "request_body"
    assert _js_ts_source_kind("process.env.API_KEY") == "env"
    assert _js_ts_source_kind("db.user.findUnique({})") == "db_read"
    assert _js_ts_source_kind("localStorage.getItem('x')") == "storage"
    assert _js_ts_source_kind("constant") is None
    js_sink_cases = {
        "console.log(value)": "log",
        "fetch(value)": "external_http",
        "openai.responses.create(value)": "llm_call",
        "client.callTool(value)": "mcp_tool_call",
        "return value": "response",
        "db.user.create(value)": "db_write",
    }
    for source, expected in js_sink_cases.items():
        assert _js_ts_sink_kind(source) == expected
        assert _js_ts_rule_id_for_sink(expected)
        assert _js_ts_title_for_sink(expected)
    assert _js_ts_sink_kind("const value = 1") is None

    route_text = "export async function GET(request) { return db.user.findUnique({ where: { id: request.nextUrl } }) }"
    assert _js_ts_has_next_route_surface(Path("app/api/users/route.ts"), route_text.lower())
    assert _js_ts_has_route_or_action_surface(Path("route.ts"), route_text.lower())
    assert _js_ts_has_data_or_response(route_text.lower())
    assert _js_ts_has_request_id_access(route_text.lower())
    assert not _js_ts_has_auth_guard("const note = 'requireAuth()';")
    assert _js_ts_has_auth_guard("const user = await requireauth();")
    assert not _js_ts_has_ownership_check("router.get('/x/:id', handler)")
    assert _js_ts_has_ownership_check(
        "const user = await requireauth(); db.order.findUnique({ where: { ownerid: user.id } })"
    )
    assert _js_ts_has_express_id_route("router.get('/x/:id', handler)")
    assert _js_ts_has_server_action("'use server';")
    assert _js_ts_has_mutation("db.user.update({})")
    assert _js_ts_mentions_rls("const rls_enabled = true")
    assert not _js_ts_mentions_rls("const note = 'rls_enabled = true'")

    summaries = _collect_js_ts_function_summaries(
        Path("services/users.ts"),
        [
            "export async function findUser(id: string) {",
            "  return prisma.user.findUnique({ where: { id } });",
            "}",
            "export const safeUser = async (id) => {",
            "  return prisma.user.findUnique({ where: { id, ownerId: currentUser.id } });",
            "}",
        ],
    )
    assert [summary.name for summary in summaries] == ["findUser"]
    assert _js_ts_data_access_kind("table.from('x').select()") == "supabase_table_read"
    assert _js_ts_data_access_kind("db.collection('x').doc(id)") == "firebase_doc_read"
    assert _js_ts_data_access_kind("cursor.execute('select 1')") == "sql_query"
    assert _js_ts_data_access_kind("constant") == ""
    assert _js_ts_body_uses_param_identifier("where: { profileid }", ("profileId",))
    assert not _js_ts_body_uses_param_identifier("where: { slug }", ("slug",))
    assert _extract_braced_body("fn({ value: '}' }) tail", 3).endswith("}")
