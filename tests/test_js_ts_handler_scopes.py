from __future__ import annotations

import time
from pathlib import Path

import pytest

from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.taint import _js_ts_command_bindings


def _rules(source: str, path: str, root: Path) -> set[str]:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return {finding.rule_id for finding in KGuardScanner().scan_workspace(root, include_flow=True).findings}


def test_next_route_auth_is_evaluated_per_handler(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const session = await getServerSession();
  return Response.json(await db.user.findMany({ where: { userId: session.user.id } }));
}

export async function POST(request: Request) {
  const body = await request.json();
  return Response.json(await db.user.findUnique({ where: { id: body.id } }));
}
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/users/route.ts", tmp_path)


def test_next_route_secure_sibling_handlers_stay_quiet(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const session = await getServerSession();
  return Response.json(await db.user.findMany({ where: { userId: session.user.id } }));
}

export async function POST(request: Request) {
  const session = await getServerSession();
  const body = await request.json();
  return Response.json(await db.user.findUnique({ where: { id: body.id, userId: session.user.id } }));
}
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" not in _rules(source, "app/api/users/route.ts", tmp_path)


def test_express_idor_is_evaluated_per_route_callback(tmp_path: Path) -> None:
    source = """
router.get('/accounts/:id', async (req, res) => {
  const user = await requireAuth(req);
  const account = await db.account.findFirst({ where: { id: req.params.id, userId: user.id } });
  res.json(account);
});

router.get('/orders/:id', async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  res.json(order);
});
"""

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" in _rules(source, "src/routes.ts", tmp_path)


def test_shallow_express_idor_remains_high_without_public_collection_evidence(tmp_path: Path) -> None:
    target = tmp_path / "src/routes.ts"
    target.parent.mkdir(parents=True)
    target.write_text(
        "router.get('/pictures/:id', auth, async (req, res) => {\n"
        "  const picture = await db.picture.findUnique({ where: { id: req.params.id } });\n"
        "  res.json(picture);\n"
        "});\n",
        encoding="utf-8",
    )

    finding = next(
        finding
        for finding in KGuardScanner().scan_workspace(tmp_path, include_flow=True).findings
        if finding.rule_id == "JS_TS_EXPRESS_IDOR_ROUTE_PARAM"
    )

    assert finding.severity == "high"


def test_public_raw_collection_list_and_detail_are_not_mislabeled_as_idor(tmp_path: Path) -> None:
    source = """
router.get('/pictures', apiToken, function(req, res) {
  db.collection('pictures').find().sort({ createdAt: -1 }).toArray(function(err, pictures) {
    res.send(pictures);
  });
});

router.get('/picture/:pictureId', apiToken, function(req, res) {
  db.collection('pictures').findOne({ _id: req.params.pictureId }, function(err, picture) {
    res.send(picture);
  });
});
"""

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" not in _rules(source, "src/routes.ts", tmp_path)


@pytest.mark.parametrize(
    "list_route,detail_route",
    [
        (
            "router.get('/pictures', auth, (req, res) => {\n"
            "  db.collection('pictures').find({ ownerId: req.user.id }).toArray(function(err, pictures) {\n"
            "    res.json(pictures);\n"
            "  });\n"
            "});\n",
            "router.get('/pictures/:id', auth, (req, res) => {\n"
            "  db.collection('pictures').findOne({ _id: req.params.id }, function(err, picture) {\n"
            "    res.json(picture);\n"
            "  });\n"
            "});\n",
        ),
        (
            "router.get('/pictures', publicAudience, (req, res) => {\n"
            "  db.collection('pictures').find().toArray(function(err, pictures) {\n"
            "    res.json(pictures);\n"
            "  });\n"
            "});\n",
            "router.get('/pictures/:id', privateAudience, (req, res) => {\n"
            "  db.collection('pictures').findOne({ _id: req.params.id }, function(err, picture) {\n"
            "    res.json(picture);\n"
            "  });\n"
            "});\n",
        ),
        (
            "router.get('/pictures', auth, (req, res) => {\n"
            "  db.collection('pictures').find().toArray(function(err, pictures) {\n"
            "    res.json(pictures);\n"
            "  });\n"
            "});\n",
            "router.delete('/pictures/:id', auth, (req, res) => {\n"
            "  db.collection('pictures').findOne({ _id: req.params.id }, function(err, picture) {\n"
            "    db.collection('pictures').deleteOne({ _id: req.params.id });\n"
            "    res.json(picture);\n"
            "  });\n"
            "});\n",
        ),
    ],
)
def test_collection_peer_does_not_hide_scoped_write_or_audience_idor(
    tmp_path: Path,
    list_route: str,
    detail_route: str,
) -> None:
    rules = _rules(list_route + "\n" + detail_route, "src/routes.ts", tmp_path)

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" in rules


def test_server_action_auth_is_evaluated_per_exported_action(tmp_path: Path) -> None:
    source = """
'use server';

export async function updateOwnProfile(input: Input) {
  const user = await requireAuth();
  return db.profile.update({ where: { userId: user.id }, data: input });
}

export async function deleteAnyProfile(input: Input) {
  return db.profile.delete({ where: { id: input.id } });
}
"""

    assert "JS_TS_NEXT_SERVER_ACTION_AUTH_BOUNDARY_WEAK" in _rules(source, "app/actions/profile.ts", tmp_path)


def test_next_route_guard_after_response_does_not_satisfy_boundary(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const data = await db.user.findMany();
  const response = Response.json(data);
  await requireAuth();
  return response;
}
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/users/route.ts", tmp_path)


def test_local_noop_require_auth_helper_does_not_satisfy_boundary(tmp_path: Path) -> None:
    source = """
function requireAuth() {
  return true;
}

export async function GET(request: Request) {
  await requireAuth();
  return Response.json(await db.user.findMany());
}
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/users/route.ts", tmp_path)


def test_multiline_request_to_command_flow_is_detected(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  const body =
    await request.json();
  const command =
    body.command;
  exec(
    command
  );
  return Response.json({ ok: true });
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(source, "app/api/run/route.ts", tmp_path)


@pytest.mark.parametrize(
    "sink",
    [
        "const match = pattern.exec(body.command);",
        "const match = pattern . exec(body.command);",
        "const match = /[a-z]+/.exec(body.command);",
        "cordova.exec(onSuccess, onFailure, 'Plugin', 'run', [body.command]);",
        "customShell.exec(body.command);",
    ],
)
def test_non_process_exec_receivers_are_not_command_sinks(
    tmp_path: Path,
    sink: str,
) -> None:
    source = f"""
export async function POST(request: Request) {{
  const body = await request.json();
  const pattern = /[a-z]+/;
  {sink}
  return Response.json({{ ok: true }});
}}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/match/route.ts",
        tmp_path,
    )


@pytest.mark.parametrize(
    ("binding", "sink"),
    [
        ("import * as cp from 'node:child_process';", "cp.exec(command);"),
        ("import * as cp from 'node:child_process';", "cp?.exec(command);"),
        ("const cp = require('child_process');", "cp.exec(command);"),
        ("import shell from 'shelljs';", "shell.exec(command);"),
    ],
)
def test_bound_process_exec_receivers_remain_command_sinks(
    tmp_path: Path,
    binding: str,
    sink: str,
) -> None:
    source = f"""
{binding}
export async function POST(request: Request) {{
  const command = (await request.json()).command;
  {sink}
  return Response.json({{ ok: true }});
}}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_parenthesized_bound_process_receiver_remains_a_command_sink(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request) {
  const command = (await request.json()).command;
  (cp).exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


@pytest.mark.parametrize(
    "sink",
    [
        "((cp)).exec(command);",
        "(cp as any).exec(command);",
        "cp!.exec(command);",
    ],
)
def test_wrapped_bound_process_receivers_remain_command_sinks(
    tmp_path: Path,
    sink: str,
) -> None:
    source = f"""
import * as cp from 'node:child_process';
export async function POST(request: Request) {{
  const command = (await request.json()).command;
  {sink}
}}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_direct_alias_of_command_namespace_remains_a_command_sink(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
const proc = cp;
export async function POST(request: Request) {
  const command = (await request.json()).command;
  proc.exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_inline_child_process_require_remains_a_command_sink(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  const command = (await request.json()).command;
  require('node:child_process').exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_bare_exec_remains_a_conservative_sink_when_locally_defined(
    tmp_path: Path,
) -> None:
    source = """
function exec(value: string) {
  return value;
}
export async function POST(request: Request) {
  const command = (await request.json()).command;
  exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


@pytest.mark.parametrize(
    "fake_binding",
    [
        "// import * as cp from 'node:child_process';",
        "const documentation = \"import * as cp from 'node:child_process';\";",
    ],
)
def test_non_code_import_text_does_not_bind_a_command_receiver(
    tmp_path: Path,
    fake_binding: str,
) -> None:
    source = f"""
{fake_binding}
export async function POST(request: Request) {{
  const command = (await request.json()).command;
  cp.exec(command);
}}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_regex_literal_import_text_does_not_bind_a_command_receiver(
    tmp_path: Path,
) -> None:
    source = r"""
const documentation = /import * as cp from 'node:child_process'/;
export async function POST(request: Request) {
  const command = (await request.json()).command;
  cp.exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


@pytest.mark.parametrize(
    "shadow",
    [
        "const cp = /[a-z]+/;",
        "cp = /[a-z]+/;",
    ],
)
def test_local_non_process_binding_shadows_imported_command_namespace(
    tmp_path: Path,
    shadow: str,
) -> None:
    source = f"""
import * as cp from 'node:child_process';
export async function POST(request: Request) {{
  {shadow}
  const body = await request.json();
  cp.exec(body.value);
}}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_parameter_shadowing_hides_imported_command_namespace(tmp_path: Path) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request, cp: RegExp) {
  const body = await request.json();
  cp.exec(body.value);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_multiline_parameter_shadowing_hides_imported_namespace(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(
  request: Request,
  cp: RegExp,
) {
  const body = await request.json();
  cp.exec(body.value);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_local_function_declaration_shadows_imported_namespace(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request) {
  function cp() {
    return /[a-z]+/;
  }
  const body = await request.json();
  cp.exec(body.value);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_shadowed_function_does_not_hide_import_from_sibling_scope(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export function match(req: Request) {
  const cp = /[a-z]+/;
  return cp.exec(req.body.value);
}
export function run(req: Request) {
  return cp.exec(req.body.command);
}
"""
    target = tmp_path / "src/run.ts"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    findings = [
        finding
        for finding in KGuardScanner().scan_workspace(
            tmp_path,
            include_flow=True,
        ).findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
    ]

    assert [finding.line_start for finding in findings] == [8]


def test_block_scoped_shadow_does_not_hide_import_after_the_block(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request) {
  const body = await request.json();
  if (body.pattern) {
    const cp = /[a-z]+/;
    cp.exec(body.value);
  }
  cp.exec(body.command);
}
"""
    target = tmp_path / "app/api/run/route.ts"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    findings = [
        finding
        for finding in KGuardScanner().scan_workspace(
            tmp_path,
            include_flow=True,
        ).findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
    ]

    assert [finding.line_start for finding in findings] == [9]


def test_same_line_block_shadow_does_not_hide_outer_import(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request) {
  const body = await request.json();
  if (body.pattern) { const cp = /[a-z]+/; cp.exec(body.value); } cp.exec(body.command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_same_line_block_shadow_without_outer_call_is_not_a_sink(
    tmp_path: Path,
) -> None:
    source = """
import * as cp from 'node:child_process';
export async function POST(request: Request) {
  const body = await request.json();
  if (body.pattern) { const cp = /[a-z]+/; cp.exec(body.value); }
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_command_binding_projection_is_bounded_for_many_namespaces() -> None:
    source = "\n".join(
        (
            f"const cp{index} = require('node:child_process'); "
            f"cp{index}.exec(value);"
        )
        for index in range(2000)
    )

    started = time.perf_counter()
    bindings = _js_ts_command_bindings(source)
    duration = time.perf_counter() - started

    assert len(bindings.events) == 4000
    assert duration < 2.5


def test_repeated_command_rebinding_keeps_workspace_scan_near_linear(
    tmp_path: Path,
) -> None:
    source = "\n".join(
        (
            "import * as cp from 'node:child_process';",
            "export async function POST(request: Request) {",
            "const body = await request.json();",
            *(
                "cp = cp; cp.exec(body.command);"
                for _ in range(2000)
            ),
            "}",
        )
    )
    target = tmp_path / "app/api/run/route.ts"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    started = time.perf_counter()
    report = KGuardScanner().scan_workspace(tmp_path, include_flow=True)
    duration = time.perf_counter() - started
    command_findings = [
        finding
        for finding in report.findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
    ]

    assert len(command_findings) == 32
    assert duration < 2.5


def test_local_command_rebinding_restores_command_namespace(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  let cp = /[a-z]+/;
  cp = require('node:child_process');
  const body = await request.json();
  cp.exec(body.value);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_unbound_spawn_receiver_is_not_a_process_argument_sink(tmp_path: Path) -> None:
    source = """
export function run(req: Request) {
  customRunner.spawn('/usr/bin/id', [req.body.argument]);
}
"""

    rules = _rules(source, "app/api/run/route.ts", tmp_path)

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in rules
    assert "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT" not in rules


def test_bound_spawn_receiver_keeps_process_argument_review(tmp_path: Path) -> None:
    source = """
import * as cp from 'node:child_process';
export function run(req: Request) {
  cp.spawn('/usr/bin/id', [req.body.argument]);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT" in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_multiline_next_handler_distinguishes_destructured_params_from_function_body(
    tmp_path: Path,
) -> None:
    source = """
export async function POST(request: Request, { params }: { params: { id: string } }) {
  const body =
    await request.json();
  exec(
    body.command
  );
  return Response.json({ id: params.id });
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(source, "app/api/run/[id]/route.ts", tmp_path)


def test_multiline_request_to_parameterized_sql_still_requires_query_structure_taint(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  const body =
    await request.json();
  await db.query(
    'select * from users where id = ?',
    [body.id]
  );
  return Response.json({ ok: true });
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_SQL" not in _rules(source, "app/api/users/route.ts", tmp_path)


def test_supabase_route_without_auth_or_rls_boundary_is_reported(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
  const { data } = await supabase.from('profiles').select('*');
  return Response.json(data);
}
"""

    assert "JS_TS_SUPABASE_RLS_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/profiles/route.ts", tmp_path)


def test_supabase_user_scoped_route_does_not_raise_rls_boundary(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const supabase = createServerClient(request);
  const { data: { user } } = await supabase.auth.getUser();
  const { data } = await supabase.from('profiles').select('*').eq('user_id', user.id);
  return Response.json(data);
}
"""

    assert "JS_TS_SUPABASE_RLS_AUTH_BOUNDARY_WEAK" not in _rules(source, "app/api/profiles/route.ts", tmp_path)


def test_firebase_admin_route_with_request_document_id_requires_auth(tmp_path: Path) -> None:
    source = """
import admin from 'firebase-admin';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const snapshot = await admin.firestore().collection('profiles').doc(params.id).get();
  return Response.json(snapshot.data());
}
"""

    assert "JS_TS_FIREBASE_ADMIN_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/profiles/[id]/route.ts", tmp_path)


def test_firebase_admin_route_with_auth_boundary_stays_quiet(tmp_path: Path) -> None:
    source = """
import admin from 'firebase-admin';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const user = await requireAuth(request);
  const snapshot = await admin.firestore().collection('profiles').doc(params.id).get();
  return Response.json({ profile: snapshot.data(), viewer: user.id });
}
"""

    assert "JS_TS_FIREBASE_ADMIN_AUTH_BOUNDARY_WEAK" not in _rules(source, "app/api/profiles/[id]/route.ts", tmp_path)


def test_route_to_service_id_lookup_is_reported_across_files(tmp_path: Path) -> None:
    service = tmp_path / "src/services/orders.ts"
    service.parent.mkdir(parents=True, exist_ok=True)
    service.write_text(
        """
export async function getOrder(id: string) {
  return db.order.findUnique({ where: { id } });
}
""",
        encoding="utf-8",
    )
    route = """
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const order = await getOrder(params.id);
  return Response.json(order);
}
"""

    assert "JS_TS_INTERPROCEDURAL_ROUTE_SERVICE_IDOR" in _rules(route, "app/api/orders/[id]/route.ts", tmp_path)


@pytest.mark.parametrize("suffix", ["mts", "cts", "vue", "svelte"])
def test_collected_js_ts_module_and_component_extensions_are_analyzed(tmp_path: Path, suffix: str) -> None:
    source = """
export async function POST(request: Request) {
  const command = (await request.json()).command;
  exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(source, f"src/danger.{suffix}", tmp_path)


def test_request_json_destructuring_alias_reaches_command_sink(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  await requireAuth();
  const { command: cmd } = await request.json();
  exec(cmd);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(source, "app/api/run/route.ts", tmp_path)


def test_safe_reassignment_kills_previous_taint(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  let command = (await request.json()).command;
  command = 'fixed-command';
  exec(command);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in _rules(source, "app/api/run/route.ts", tmp_path)


def test_spawn_shell_command_argument_is_taint_relevant(tmp_path: Path) -> None:
    source = """
export async function POST(request: Request) {
  const body = await request.json();
  spawn('sh', ['-c', body.command]);
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in _rules(source, "app/api/run/route.ts", tmp_path)


def test_parameterized_query_object_does_not_taint_sql_structure(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const body = await request.json();
  return pool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [body.id] });
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_SQL" not in _rules(source, "app/api/users/route.ts", tmp_path)


def test_prisma_parameterized_tagged_template_stays_quiet(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const body = await request.json();
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${body.id}`;
}
"""

    assert "WEB_UNTRUSTED_INPUT_TO_SQL" not in _rules(source, "app/api/users/route.ts", tmp_path)


@pytest.mark.parametrize(
    "guard",
    [
        "await getServerSession();",
        "if (false) await requireAuth();",
        "const requireAuth = () => true; await requireAuth();",
    ],
)
def test_non_enforcing_auth_calls_do_not_satisfy_route_boundary(tmp_path: Path, guard: str) -> None:
    source = f"""
export async function GET(request: Request) {{
  {guard}
  return Response.json(await db.user.findMany());
}}
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/users/route.ts", tmp_path)


def test_typed_const_route_handler_is_scoped(tmp_path: Path) -> None:
    source = """
export async function GET(request: Request) {
  const user = await requireAuth();
  return Response.json({ id: user.id });
}

export const POST: RouteHandler = async (request) => {
  const body = await request.json();
  return Response.json(await db.user.findUnique({ where: { id: body.id } }));
};
"""

    assert "JS_TS_NEXT_ROUTE_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/users/route.ts", tmp_path)


def test_named_express_order_id_handler_requires_ownership(tmp_path: Path) -> None:
    source = """
async function getOrder(req, res) {
  const order = await db.order.findUnique({ where: { id: req.params.orderId } });
  res.json(order);
}

router.get('/orders/:orderId', getOrder);
"""

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" in _rules(source, "src/routes.ts", tmp_path)


def test_unused_user_id_name_does_not_prove_query_ownership(tmp_path: Path) -> None:
    source = """
router.get('/orders/:orderId', async (req, res) => {
  const user = await requireAuth(req);
  const userId = user.id;
  const order = await db.order.findUnique({ where: { id: req.params.orderId } });
  res.json(order);
});
"""

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" in _rules(source, "src/routes.ts", tmp_path)


def test_interprocedural_service_call_requires_request_derived_argument(tmp_path: Path) -> None:
    service = tmp_path / "src/services/catalog.ts"
    service.parent.mkdir(parents=True, exist_ok=True)
    service.write_text(
        """
export async function load(id: string) {
  return db.catalog.findUnique({ where: { id } });
}
""",
        encoding="utf-8",
    )
    route = """
export async function GET(request: Request) {
  const requested = request.nextUrl.searchParams.get('id');
  const item = await load('public-catalog-entry');
  return Response.json({ item, requested });
}
"""

    assert "JS_TS_INTERPROCEDURAL_ROUTE_SERVICE_IDOR" not in _rules(route, "app/api/catalog/route.ts", tmp_path)


def test_js_ts_default_budget_completes_medium_flow_file(tmp_path: Path) -> None:
    sinks = "\n".join(f"  console.log(body.value{i});" for i in range(24))
    source = f"""
export async function POST(request: Request) {{
  const body = await request.json();
{sinks}
  exec(body.command);
}}
"""

    assert "STATIC_ANALYSIS_LIMIT_REACHED" not in _rules(
        source,
        "app/api/run/route.ts",
        tmp_path,
    )


def test_js_ts_explicit_low_flow_budget_still_fails_closed(
    tmp_path: Path,
) -> None:
    sinks = "\n".join(f"  console.log(body.value{i});" for i in range(24))
    target = tmp_path / "app/api/run/route.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        f"""
export async function POST(request: Request) {{
  const body = await request.json();
{sinks}
  exec(body.command);
}}
""",
        encoding="utf-8",
    )
    scanner = KGuardScanner()
    scanner.flow_analyzer.ast_taint.max_js_ts_edges_per_file = 8
    scanner.flow_analyzer.ast_taint.max_js_ts_findings_per_rule_per_file = 8

    rules = {
        finding.rule_id
        for finding in scanner.scan_workspace(
            tmp_path,
            include_flow=True,
        ).findings
    }

    assert "STATIC_ANALYSIS_LIMIT_REACHED" in rules


def test_sibling_authenticated_handler_does_not_mask_weak_supabase_route(tmp_path: Path) -> None:
    source = """
import { createClient } from '@supabase/supabase-js';

export async function GET() {
  const session = await getServerSession();
  if (!session) return new Response('unauthorized', { status: 401 });
  return Response.json({ id: session.user.id });
}

export async function POST(request: Request) {
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);
  const { data } = await supabase.from('profiles').select('*');
  return Response.json(data);
}
"""

    assert "JS_TS_SUPABASE_RLS_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/profiles/route.ts", tmp_path)


def test_sibling_authenticated_handler_does_not_mask_weak_firebase_route(tmp_path: Path) -> None:
    source = """
import { getFirestore } from 'firebase-admin/firestore';

export async function GET() {
  const user = await requireAuth();
  return Response.json({ id: user.id });
}

export async function POST(request: Request, { params }: { params: { accountId: string } }) {
  const record = await getFirestore().collection('accounts').doc(params.accountId).get();
  return Response.json(record.data());
}
"""

    assert "JS_TS_FIREBASE_ADMIN_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/accounts/route.ts", tmp_path)


def test_string_literal_owner_hint_does_not_satisfy_express_ownership(tmp_path: Path) -> None:
    source = """
router.get('/orders/:orderId', async (req, res) => {
  const user = await requireAuth(req);
  const order = await db.order.findUnique({ where: { id: req.params.orderId } });
  const migrationNote = 'user_id: TODO';
  res.json({ order, migrationNote, viewer: user.id });
});
"""

    assert "JS_TS_EXPRESS_IDOR_ROUTE_PARAM" in _rules(source, "src/routes/orders.ts", tmp_path)


def test_local_helper_cannot_hide_weak_supabase_access_from_route_scope(tmp_path: Path) -> None:
    source = """
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

async function listAllProfiles() {
  return supabase.from('profiles').select('*');
}

export async function GET() {
  const session = await getServerSession();
  if (!session) return new Response('unauthorized', { status: 401 });
  return Response.json({ id: session.user.id });
}

export async function POST() {
  return Response.json(await listAllProfiles());
}
"""

    assert "JS_TS_SUPABASE_RLS_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/profiles/route.ts", tmp_path)


def test_firebase_admin_collection_listing_requires_auth_without_request_id(tmp_path: Path) -> None:
    source = """
import { getFirestore } from 'firebase-admin/firestore';

async function listAllAccounts() {
  return getFirestore().collection('accounts').get();
}

export async function GET() {
  return Response.json(await listAllAccounts());
}
"""

    assert "JS_TS_FIREBASE_ADMIN_AUTH_BOUNDARY_WEAK" in _rules(source, "app/api/accounts/route.ts", tmp_path)
